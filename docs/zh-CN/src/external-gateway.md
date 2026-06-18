# External Gateway

External gateway 把进程外程序以 Provider 或 Source projection 接入 Nexus。gRPC 和 WebSocket 是同一个 session 协议的两种传输实现。

## 角色

Provider session 暴露由所选 installation projection 声明的远端 effect handler。`RoleReady` 确认 daemon 选定的 session context 后，daemon 为该 ready session 注册这些 projection binding，并且只向已注册 effect 下发 invocation。

Source session 发送入站事件，也可以接收 daemon 的 outbound command。无论 Source event 通过 gRPC 还是 WebSocket 到达，都会进入同一套 schema、policy、capacity、dedupe 和 taint 路径。

Provider 和 Source 是唯一的外部 projection role。

## 传输

External gRPC 监听 `[server].external_grpc_addr` 或 `NEXUS_EXTERNAL_GRPC_ADDR`，并提供 `nexus.v1.external.ExternalService.Session`。

External WebSocket 监听 `[server].external_websocket_addr` 或 `NEXUS_EXTERNAL_WEBSOCKET_ADDR`，在 `/ws` 上提供同一套逻辑 session frame。

两种传输使用同一个 daemon 侧 session handler 和同一套 Provider/Source 准入 state。

## 配置

`[external_gateway.grpc]` 和 `[external_gateway.websocket]` 使用同一组 Provider/Source 限制 key：

```toml
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
```

`source_dedupe_window_ms` 限制 Source event id 去重保留窗口，也限制 Source outbound command 在 result、deadline 或 session drain 后的 command idempotency 保留窗口。

Provider in-flight 上限作用于每个 ready Provider session、该 session 内每个 acting identity、该 session 内每个 effect path。

Source command 上限作用于每个 ready Source session。command rate limit 作用于每个 Source projection。

Source event 的 payload 大小限制、stream 容量、溢出行为和 event-ingress 速率限制在每个 Source projection 上声明。

## WebSocket 传输限制

External WebSocket 有传输层限制：

```toml
[external_gateway.websocket.transport]
max_frame_bytes = 1048576
first_frame_timeout_ms = 10000
idle_timeout_ms = 300000
max_connections = 256
```

这些值会在监听启动前由 `nexus-gateway-websocket` 限制到硬上限内。

## 传输安全

External gRPC 支持 `production_tls`、`mtls`、`trusted_reverse_proxy`、`local_trusted`、`unsafe_plaintext` 和 `disabled_for_test`。

External WebSocket 是明文监听器。外部 TLS 终止使用 `trusted_reverse_proxy`，仅 loopback 部署使用 `local_trusted`，只有部署明确接受明文时才使用 `unsafe_plaintext`。`production_tls` 和 `mtls` 在 WebSocket 明文监听器上会拒绝启动。

## Session 状态

已批准 session state 读取自：

```text
state://kernel/external-sessions/<installation_id>/<role>
```

session record 必须匹配连接方的 installation id 和 role。daemon 会在业务 frame 流动前拒绝缺失、不匹配、已撤销或非 ready 的 session record。

## Provider 流程

Provider 调用只会发送给 installation projection 声明并已为 ready session 注册的投影 effect，且调用输入必须匹配 Provider projection 的 `input_schema`。Provider 结果只接受 daemon 已登记的在途 invocation。结果必须来自同一个 ready Provider session generation，在 invocation deadline 前到达，并且不超过该 invocation 登记的结果大小限制。

invocation deadline 到达时，daemon 会尽力发送 `ProviderCancel` 控制帧，再在本地释放 pending invocation。这是协作取消信号，不承诺撤销已经发生的外部副作用。

## Source 流程

Source event 只会在 session 处于 ready 状态且 generation 字段匹配 daemon 裁定的上下文后准入。event id 在 state 中按固定保留窗口去重。

携带 `stream_id` 和 `seq` 的事件只按 stream 局部顺序 append。重复 event id 只在首次 append 已提交后返回 duplicate ack。如果重试在原事件仍处于 pending 状态时到达，会作为 backpressure 拒绝。

启用 outbound command 的 Source projection 必须声明 command action schema 和成功 result schema。daemon 会在发送 command 前校验 action，并在解析已登记 command 前校验成功 result。

## SecureEnvelope

session 协议使用 `SecureEnvelope` 承载 AEAD 保护的业务/控制 frame。认证附加数据绑定 projection、role、session、transcript hash、key epoch、frame type、sequence number、binding generation 和 credential generation。

接收端按 envelope stream 维护固定大小的 replay window。重复、超出保留窗口和跳跃过远的 sequence number 会在 frame body 解码前被拒绝。
