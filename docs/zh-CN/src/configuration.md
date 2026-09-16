# 配置

`xolotl.toml` 是引导配置。它控制存储、监听地址、root 引导凭据、external gateway 限制、控制台资源限制和传输安全设置。

创建本地配置：

```sh
cp xolotl.toml.example xolotl.toml
```

启动守护进程：

```sh
cargo run -p xolotl-daemon -- up
```

## 主要配置段

| 配置段 | 用途 |
| --- | --- |
| `[storage]` | 选择 redb 持久存储或内存存储 |
| `[server]` | 通过 `console_addr`、`application_grpc_addr`、`external_grpc_addr` 和 `external_websocket_addr` 绑定监听器 |
| `[application_gateway]` | 选择 State profile，设置应用 gRPC 帧大小、上传与输出并发、输出驻留窗口和等待窗口 |
| `[external_gateway.grpc]` | 设置 external gRPC 监听器的 Provider/Source session 限制 |
| `[external_gateway.websocket]` | 设置 external WebSocket 监听器的同一组 Provider/Source session 限制 |
| `[external_gateway.websocket.transport]` | 设置 WebSocket frame 大小、first-frame 超时、idle 超时和总连接数 |
| `[console.root]` | 预置 root 凭据 |
| `[console.auth]` | 设置会话 TTL、会话数量和 Argon2 校验并发限制 |
| `[console.ws]` | 设置控制台 WebSocket 的 frame、连接数、idle、速率、订阅数、结果大小、已编码事件队列和所有帧的发送限制 |

对应 `[server]` 字段缺失时，`xolotld` 还会读取 `XOLOTL_CONSOLE_ADDR`、`XOLOTL_APPLICATION_GRPC_ADDR`、`XOLOTL_EXTERNAL_GRPC_ADDR` 和 `XOLOTL_EXTERNAL_WEBSOCKET_ADDR`。配置字段和环境变量都缺失时，该监听保持关闭。

应用监听器需要可选的 `application-grpc` feature。启用地址前通过 Console 创建 profile；
完整配置和上传协议见[应用网关](application-gateway.md)。

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
# certificate_chain_path = "/etc/xolotl/external-grpc-cert.pem"
# private_key_path = "/etc/xolotl/external-grpc-key.pem"
# client_trust_roots = ["/etc/xolotl/external-client-ca.pem"]
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

运行时 Provider 设置、模型路由、组、绑定、进程内 Provider/Source projection 声明、外部 Provider/Source installation 声明和策略管理状态都属于 Xolotl state，并通过 Console WebSocket action 管理。External projection 是 installation 声明的一部分。External 声明使用 `external.*`，inference 声明使用 `inference.*`，进程内 projection 声明通过 `config.*` 写入 `state://kernel/projections/in-process/<id>`。泛用 `config.*` action 会拒绝已经有专用动作族的运行时配置路径。

`xolotl-standard` Cargo feature 决定哪些进程内实现被编译进宿主二进制。可选进程内 projection 声明位于
`state://kernel/projections/in-process/<id>`。reconcile 状态写在
`state://kernel/projection-status/in-process/<id>`，通过
`projection.in_process.status.*` 读取；状态会区分期望声明版本和当前 active registry 版本。
嵌入式宿主还可以用 `StandardConfig::with_modules` 选择实际安装哪些已编译的
standard-core 模块；代码编译进二进制并不等于已经公开为 Resource。

HTTP inference provider 只有在宿主二进制启用对应 `xolotl-standard` feature 时才会编译。
运行时声明放在 `state://kernel/inference/*` 和 `state://kernel/routing/inference`；
backend 记录只保存 `state://vault/inference/<backend>/api_key` 这类 secret 引用，
不保存原始 API key。

`InferenceBackendDef.io_window_bytes` 设置请求编码和解析工作的窗口，默认 16,384 字节，
接受任意正整数。单字节窗口也支持跨窗口的 UTF-8 字符和 JSON 转义；该窗口不限制请求、
响应或 SSE 事件的总长度。输出通道仍通过 `StreamWindow` 独立配置，HTTP 库另行持有其
传输缓冲区。
记录校验完成后，已选文本按此窗口分块输出，并保留完整 UTF-8 字符；窗口小于一个字符时，
该块最多包含四字节。输出通道计入编码后的块及其来源元数据。

`response_limits` 将结果物化策略独立配置：

- `max_materialized_bytes`：单个 unary 响应或原子 SSE 记录内同时保留的已选文本和数字 token 字节。
- `max_materialized_nodes`：保留的已选值节点数，包含空值。
- `max_json_frames`：同时打开的 JSON 容器数，包含被跳过的数据。

所有上限均为可选；未设置的维度不施加配额。字节和节点计数是逻辑准入单位，不代表分配器
或进程 RSS 上限。已知控制标签和字段名有固定存储开销，不计入已选 token 字节。
最终 unary 输出及每条原子 SSE 增量仍需驻留存储，应用可以显式约束这些
结果的物化，而不限制任务累计数据量。未使用的 Provider 字段会增量校验，不会组成完整 JSON
包。例如，OpenAI Responses 完成快照中重复的输出文本不会被保留。

SSE 记录必须完整结束且 JSON 校验通过，才会交付该记录中选中的 delta。后到的错误或非法
后缀不会使同一记录的前缀提前发布。解析器只移除流开头的一次 UTF-8 BOM，并同样校验跳过的
数据。各适配器保留其声明的 delta 语义，不会凭文本重复自行猜测累计快照。
HTTP 错误诊断固定读取最多 8 KiB 前缀，展示最多 512 个脱敏字符，与成功响应的准入相互
独立。达到前缀上限后停止读取，无需等待服务端结束响应体；若服务端在此之前停滞，仍需
请求取消或客户端超时处理。字节上限不会隐式施加响应持续时间策略。

嵌入式宿主通过 `StandardConfig::with_object_store` 显式安装对象能力。
`ObjectStore` 分别接收读、写和删除适配器；
`xolotl-storage-fs::FileObjectStore::open(root)` 提供文件实现。
Fetch 和文件读取的大型 unary 输出、Blob 写入及 Tensor 写入需要对象写入端口；
Blob 读取和删除需要对应端口。流式 Fetch 和文件读取无需安装对象存储。

控制台认证、WebSocket 和传输安全字段是部署设置。能力检查、二次确认门槛、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。
