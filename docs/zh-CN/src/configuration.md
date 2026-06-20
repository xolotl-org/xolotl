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

| 配置段 | 用途 |
| --- | --- |
| `[storage]` | 选择 redb 持久存储或内存存储。 |
| `[server]` | 通过 `console_addr`、`external_grpc_addr` 和 `external_websocket_addr` 绑定监听器。 |
| `[external_gateway.grpc]` | 设置 external gRPC 监听器的 Provider/Source session 限制。 |
| `[external_gateway.websocket]` | 设置 external WebSocket 监听器的同一组 Provider/Source session 限制。 |
| `[external_gateway.websocket.transport]` | 设置 WebSocket frame 大小、first-frame 超时、idle 超时和总连接数。 |
| `[console.root]` | 预置 root 凭据。 |
| `[console.auth]` | 设置会话 TTL、会话数量和 Argon2 校验并发限制。 |
| `[console.ws]` | 设置控制台 WebSocket 的 frame、连接数、idle、速率、订阅数、结果大小和事件背压限制。 |

对应 `[server]` 字段缺失时，`nexusd` 还会读取 `NEXUS_CONSOLE_ADDR`、`NEXUS_EXTERNAL_GRPC_ADDR` 和 `NEXUS_EXTERNAL_WEBSOCKET_ADDR`。配置字段和环境变量都缺失时，该监听保持关闭。

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
provider_max_inline_result_bytes = 65536
source_max_in_flight_commands = 1024
source_command_max_inline_result_bytes = 65536
source_command_rate_limit_window_ms = 60000
source_command_rate_limit_max = 600

[external_gateway.websocket]
source_dedupe_window_ms = 86400000
provider_max_in_flight_invocations = 1024
provider_max_in_flight_per_identity = 256
provider_max_in_flight_per_effect = 256
provider_max_inline_result_bytes = 65536
source_max_in_flight_commands = 1024
source_command_max_inline_result_bytes = 65536
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
`provider_max_inline_result_bytes` 限制 Provider 成功和错误结果的 inline 大小。

`source_max_in_flight_commands`、`source_command_rate_limit_window_ms` 和 `source_command_rate_limit_max` 限制每个 ready Source session 和每个 Source projection 的 outbound command 分发。
`source_command_max_inline_result_bytes` 限制 Source command 成功和错误结果的 inline 大小。

Source event 的 payload 大小限制、stream 容量、溢出行为和 event-ingress 速率限制在每个 Source projection 上声明。

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

External WebSocket 是明文监听器。外部 TLS 终止使用 `trusted_reverse_proxy`，仅 loopback 部署使用 `local_trusted`，否则必须显式 `unsafe_plaintext`。`production_tls` 和 `mtls` 在该明文监听器上会拒绝启动。

控制台传输安全单独配置：

```toml
[console.transport_security]
mode = "local_trusted"
```

daemon 的控制台监听器当前是明文监听器。`local_trusted` 只用于 loopback
`console_addr`；如果 TLS 由可信前置代理终止，使用 `trusted_reverse_proxy`，并在
`trusted_proxy_peers` 中列出直连代理地址。除非控制台监听器配置了 daemon
持有的 TLS 材料，否则 `production_tls` 会拒绝启动。

## 运行时配置

运行时 Provider 设置、模型路由、组、绑定、进程内 Provider/Source projection 声明、外部 Provider/Source installation 声明和策略管理状态都属于 Nexus state，并通过 Console WebSocket action 管理。External projection 是 installation 声明的一部分。External 声明使用 `external.*`，inference 声明使用 `inference.*`，进程内 projection 声明通过 `config.*` 写入 `state://kernel/projections/in-process/<id>`。泛用 `config.*` action 会拒绝已经有专用动作族的运行时配置路径。

`nexus-standard` Cargo feature 决定哪些进程内实现被编译进宿主二进制。可选进程内 projection 声明位于
`state://kernel/projections/in-process/<id>`。reconcile 状态写在
`state://kernel/projection-status/in-process/<id>`，通过
`projection.in_process.status.*` 读取；状态会区分期望声明版本和当前 active registry 版本。
嵌入式宿主还可以用 `StandardConfig::with_modules` 选择实际安装哪些已编译的
standard-core 模块；代码编译进二进制并不等于已经公开为 Resource。

HTTP inference provider 只有在宿主二进制启用对应 `nexus-standard` feature 时才会编译。
运行时声明放在 `state://kernel/inference/*` 和 `state://kernel/routing/inference`；
backend 记录只保存 `state://vault/inference/<backend>/api_key` 这类 secret 引用，
不保存原始 API key。

控制台认证、WebSocket 和传输安全字段是部署设置。能力检查、二次确认门槛、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。
