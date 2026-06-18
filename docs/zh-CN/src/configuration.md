# 配置

`nexus.toml` 是引导配置。它控制存储、监听地址、root 引导凭据、external gateway 限制、控制台资源限制和传输安全设置。

创建本地配置：

```sh
cp nexus.toml.example nexus.toml
```

启动守护进程：

```sh
cargo run -p nexus-daemon -- up
```

## 主要配置段

`[storage]` 选择 redb 持久存储或内存存储。

`[server]` 设置监听绑定地址：

- `console_addr`
- `external_grpc_addr`
- `external_websocket_addr`

对应配置字段缺失时，`nexusd` 还会读取 `NEXUS_CONSOLE_ADDR`、`NEXUS_EXTERNAL_GRPC_ADDR` 和 `NEXUS_EXTERNAL_WEBSOCKET_ADDR`。配置字段和环境变量都缺失时，该监听保持关闭。

`[external_gateway.grpc]` 配置 external gRPC listener 的 Provider/Source session 限制。

`[external_gateway.websocket]` 配置 external WebSocket listener 的同一组 Provider/Source session 限制。

`[external_gateway.websocket.transport]` 配置 WebSocket frame size、first-frame timeout、idle timeout 和总连接数。

`[console.root]` 可预置 root 凭据。

`[console.auth]` 设置会话 TTL、会话数量和 Argon2 校验并发限制。

`[console.ws]` 设置控制台 WebSocket 的 frame、连接数、idle、速率、订阅数、结果大小和事件背压限制。

## External Gateway

External gRPC 和 external WebSocket 提供同一套 Provider/Source session 协议：

```toml
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway.grpc]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
source_max_in_flight_commands = 1024
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
source_max_in_flight_commands = 1024
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket.transport]
max_frame_bytes = 1048576
first_frame_timeout_ms = 10000
idle_timeout_ms = 300000
max_connections = 256
```

`source_dedupe_window_ms` 限制 Source event id 去重保留窗口，也限制 Source outbound command 在 result、deadline 或 session drain 后的 command idempotency 保留窗口。

`provider_max_in_flight_invocations`、`provider_max_in_flight_per_identity` 和 `provider_max_in_flight_per_effect` 限制每个 ready Provider session 的 pending invoke。

`source_max_in_flight_commands`、`source_command_rate_limit_window_ms` 和 `source_command_rate_limit_max` 限制每个 ready Source session 和每个 Source projection 的 outbound command dispatch。

Source event payload-size limit、stream capacity、overflow behavior 和 event-ingress rate limit 在每个 Source projection 上声明。

## 传输安全

External gRPC 传输安全：

```toml
[external_gateway.grpc.transport_security]
mode = "local_trusted"
# trusted_proxy_peers = ["127.0.0.1"]
# honor_x_forwarded_proto = true
# honor_x_forwarded_host = true
# honor_x_forwarded_for = true
# certificate_chain_path = "/etc/nexus/external-grpc-cert.pem"
# private_key_path = "/etc/nexus/external-grpc-key.pem"
# client_trust_roots = ["/etc/nexus/external-client-ca.pem"]
# unsafe_relaxations = ["ignore_origin_port"]
```

External gRPC 支持 `production_tls`、`mtls`、`trusted_reverse_proxy`、`local_trusted`、`unsafe_plaintext` 和 `disabled_for_test`。`production_tls` 要求 `certificate_chain_path` 和 `private_key_path`。`mtls` 还要求 `client_trust_roots`。`trusted_reverse_proxy` 必须配置 `trusted_proxy_peers`；只有直连 peer 命中可信代理时才采信 forwarded header。

External WebSocket 传输安全：

```toml
[external_gateway.websocket.transport_security]
mode = "local_trusted"
# trusted_proxy_peers = ["127.0.0.1"]
# honor_x_forwarded_proto = true
# honor_x_forwarded_host = true
# honor_x_forwarded_for = true
# unsafe_relaxations = ["ignore_origin_port"]
```

External WebSocket 是 plain listener。外部 TLS 终止使用 `trusted_reverse_proxy`，仅 loopback 部署使用 `local_trusted`，否则必须显式 `unsafe_plaintext`。`production_tls` 和 `mtls` 对该 listener fail closed。

控制台传输安全单独配置：

```toml
[console.transport_security]
mode = "local_trusted"
```

daemon 的控制台 listener 当前是 plain listener。`local_trusted` 只用于 loopback
`console_addr`；如果 TLS 由可信前置代理终止，使用 `trusted_reverse_proxy`，并在
`trusted_proxy_peers` 中列出直连代理地址。除非控制台 listener 配置了 daemon
持有的 TLS material，否则 `production_tls` 会 fail closed。

## 运行时配置

运行时 Provider 设置、模型路由、组、绑定、进程内 Provider/Source projection 声明、外部 Provider/Source installation 声明和策略管理状态都属于 Nexus state，并通过 Console WebSocket action 管理。External projection 是 installation 声明的一部分。External 声明使用 `external.*`，inference 声明使用 `inference.*`，进程内 projection 声明使用 `projection.in_process.*`。泛用 `config.*` action 会拒绝已经有专用 action family 的运行时配置路径。

`nexus-standard` Cargo feature 决定哪些进程内实现被编译进宿主二进制。可选进程内 projection 声明位于
`state://kernel/projections/in-process/<id>`。

HTTP inference provider 只有在宿主二进制启用对应 `nexus-standard` feature 时才会编译。
运行时声明放在 `state://kernel/inference/*` 和 `state://kernel/routing/inference`；
backend 记录只保存 `state://vault/inference/<backend>/api_key` 这类 secret 引用，
不保存原始 API key。

控制台认证、WebSocket 和传输安全字段是部署设置。能力检查、二次确认门槛、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。
