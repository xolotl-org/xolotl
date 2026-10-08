# 配置

`xolotl.toml` 是引导配置。它控制存储、监听地址、root 引导凭据、external gateway 限制、控制台资源限制和传输安全设置。默认的 `xolotl.toml` 可以不存在；设置 `XOLOTL_CONFIG` 后，指定文件必须存在且可读，否则守护进程启动失败。文件内的相对路径（包括存储与 TLS 材料路径）以守护进程的工作目录为基准，与配置文件的位置无关。若启动时工作目录可能变化，应使用绝对路径。

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
| `[storage]` | 后端、State 历史模式、Source 有序流额度 |
| `[storage.history_maintenance]` | `full` State 历史的自动裁剪窗口和批次预算 |
| `[server]` | 通过 `console_addr`、`application_grpc_addr`、`external_grpc_addr` 和 `external_websocket_addr` 绑定监听器 |
| `[storage.observations]` | 显式启用观察留存，必须填写正数 `max_records`、`max_encoded_bytes`、`max_record_bytes`；单条字节上限不能超过总字节预算。默认不启用。选定的记录写入满额时拒绝，不静默淘汰证据；编码字节预算不是 RSS 上限。执行身份和业务持久数据独立于观察留存。 |
| `[application_gateway]` | 应用 profile、gRPC 帧、并发、输出窗口和超时 |
| `[application_gateway.request_storage]` | `max_records`、`max_bytes`、`max_record_bytes` 限制请求证据；`retry_epoch_ms` 独立安排宿主关闭重试范围，默认 900000 ms，接受 1–86400000，超限不截断。回收满足条件的已结算证据，未决及未知工作继续占额。见[应用 Gateway](application-gateway.md)。 |
| `[external_gateway]` | 外部传输共享的全局 Source 命令容量 |
| `[external_gateway.source_maintenance]` | Source 清理间隔与命令／存储共享批次预算 |
| `[external_gateway.grpc]` | External gRPC 的 Provider/Source session 限制 |
| `[external_gateway.websocket]` | External WebSocket 的 Provider/Source session 限制 |
| `[external_gateway.websocket.transport]` | External WebSocket 的帧、超时和连接限制 |
| `[console.root]` | 预置 root 凭据 |
| `[console.credentials]` | 提供 Console 凭据记录的宿主加密密钥；使用 redb 时必需 |
| `[external_credentials]` | 提供外部配对 vault 的独立宿主加密密钥；使用 redb 时必需 |
| `[console.auth]` | 会话、密码 hash 和外部认证准备限额；`max_external_verifications` 从断言验证持续计量到账户查询与会话或有界 continuation 准入，默认 32，范围 1–256 |
| `[console.auth.challenges]` | 公钥、Passkey、MFA 共用的持久挑战限额 |
| `[console.auth.mfa]` | 内置 TOTP、外部 Provider 使用策略和认证时限 |
| `[console.auth.mfa.totp]` | TOTP 算法、位数、周期与时钟偏差 |
| `[console.runtime]` | 宿主开放的资源、模块、外层输入 Value 的逻辑节点／深度／内联字节与执行限额；默认关闭，输入预算不是 RSS |
| `[console.runtime.budget]` | 调用及后代共享的费用、并发与 Token 上限 |
| `[console.runtime.executions]` | 当前宿主生命周期内的独立提交、结果留存、取消与权限复核配置 |
| `[console]` | 共用的调用/认证并发及 HTTP 请求体超时；`submission_retry_epoch_ms` 独立设置 daemon 按单调时钟关闭提交重试范围的间隔，默认 900000 ms，接受 1–86400000，超限拒绝而非截断；不由结果留存决定 |
| `[console.streams]` | 共用订阅数量与事件大小限制 |
| `[console.queries]` | 管理查询的分页条数与字节预算 |
| `[console.ws]` | WebSocket 连接、帧、订阅和发送队列限制 |

对应 `[server]` 字段缺失时，`xolotld` 还会读取 `XOLOTL_CONSOLE_ADDR`、`XOLOTL_APPLICATION_GRPC_ADDR`、`XOLOTL_EXTERNAL_GRPC_ADDR` 和 `XOLOTL_EXTERNAL_WEBSOCKET_ADDR`。配置字段和环境变量都缺失时，该监听保持关闭。

应用监听器需要可选的 `application-grpc` feature。启用地址前通过 Console 创建 profile；完整配置和上传协议见[应用网关](application-gateway.md)。

`[storage].state_history` 对 `redb` 和 `memory` 都默认使用 `"current_only"`：保留 State 当前值与数据来源，不提供历史查询。选择 `"full"` 才保留 `state://vault/**` 保护命名空间之外的 State 变更；Source sink 更新和 Gateway 票据变更也会使历史随写入增长。redb 在创建数据库时保存模式，换模式重开会失败。Source 凭据、Fact 和私有服务记录有各自的保留规则，关闭 State 历史不限制总存储量。redb 数据库还保存本地 `identity://...` 路径的双向目录与编号高水位；daemon 在执行前核验目录。备份时须将目录与引用这些身份编号的持久记录保留在同一数据库中。重开业务数据不会恢复程序，见[存储合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/lib.rs)。

使用 redb 时，外部配对密钥保存在加密的宿主私有 vault 中：把 `storage.path` 的扩展名替换为 `.external-credentials`，例如 `xolotl.db` 对应 `xolotl.external-credentials`。必须在 `[external_credentials] key_file` 指定独立生成的 32 字节原始随机密钥，路径须为绝对路径；Unix 下密钥文件须为私有普通文件。daemon 打开密钥与 vault 时不跟随末端符号链接，并检查权限；缺失密钥、旧明文 vault、错误密钥或损坏密文都会拒绝启动。vault 密钥若与任何 Console 当前或旧凭据密钥相同，也会被拒绝。vault 使用 AES-256-GCM-SIV，文件上限为 64 MiB；新写入通过私有临时文件和原子 rename 完成。memory 存储只在内存保存配对密钥。备份时须将 redb 数据库、vault 和独立密钥作为匹配的一组：安装／会话 State 与已签发密钥不共用事务，缺失或不匹配的密钥会使会话认证失败。配对变更会重写并同步整个 vault；ready 会话按安装 ID 查键。active-key map 没有独立数量上限，大量安装时应测量文件大小与配对延迟。直接更换 vault 密钥而不重封文件会在启动时失败；目前没有自动轮换。

内建后端不把 Console 凭据 vault 的变更写入逻辑 State 历史，vault 的历史点读会明确拒绝。redb 中的 Console 凭据记录使用宿主提供的 AES-256-GCM-SIV 密钥加密，密钥不写入 redb；旧明文记录会被拒绝。写时复制的旧物理页及备份仍可能含有旧密文，或此格式启用前的明文；加密不会擦除它们。宿主无需继续保留非 vault 历史时，应推进显式历史保留水位；daemon 只在显式配置时间窗口后自动调度。

持久 Console 存储要求在 `[console.credentials]` 中配置 `active_key_id` 和 `active_key_file`。文件必须位于绝对路径，包含恰好 32 字节原始随机数据；Unix 下须为 group／other 不可访问的普通文件。daemon 打开文件时禁止跟随末端符号链接，随后检查已打开的文件再读取。缺少密钥时拒绝启动持久存储。memory 存储未配置该段时生成仅限本进程的密钥。嵌入式 Rust 宿主须将同一个 `CredentialSealer` 提供给 root 初始化与 `ConsoleConfig.auth.credential_sealer`。

轮换时设置新的 active key，并将旧密钥作为 `[[console.credentials.previous]]` 的 `key_id`、`key_file` 保留。旧密钥只解密；账户凭据在下一次更新时才用 active key 重封，目前没有批量重封。移除旧密钥前必须确认所有依赖它的记录已重封，否则其读取会封闭失败。共用同一 State 后端的宿主必须使用一致的 key ID 和 active key。密钥文件须与对应 redb 数据库一同保护、备份；旧数据库页面和备份仍由宿主处理。

## State 历史自动维护

`full` 未配置 `[storage.history_maintenance]` 时保留所有非 vault 变更，直到嵌入宿主显式裁剪。要让 daemon 对 `redb` 或 `memory` 的全局历史水位自动分批推进，配置：

```toml
[storage]
state_history = "full"

[storage.history_maintenance]
retain_for_ms = 86400000 # 至少保留 24 小时的时间戳窗口
```

每轮目标为 `now_millis - retain_for_ms`；只有目标为正且高于已提交水位时才尝试。严格早于新水位的变更折叠为路径基线，更早的历史读取返回 `HistoryTrimmed`。高写入时历史时钟可能领先墙上时间。**此策略没有活动读者 pin，也不知道审计和重放消费者需要的最早时间。** 启用者须先确定各调用者的保留承诺；无法确定时保持自动维护关闭，由宿主手动选择水位。`current_only` 搭配该配置段会拒绝启动；`retain_for_ms` 必填且必须为正数。

| 字段 | 默认值 | 允许范围 |
| --- | ---: | ---: |
| `retain_for_ms` | 必填 | `1`–`i64::MAX` |
| `interval_ms` | `10000` | `1000`–`3600000` |
| `max_attempts_per_tick` | `16` | `1`–`64` |
| `max_batches_per_tick` | `4` | `1`–`16`，且不大于 `max_attempts_per_tick` |
| `events_per_batch` | `4096` | `1`–`4096` |
| `encoded_bytes_per_batch` | `16777216` | `1`–`16777216`（16 MiB） |

非法数值直接拒绝，不截断。每次裁剪在事件数及编码字节预算内原子提交；目标超出单次预算时，daemon 在已提交水位与失败目标之间尝试较小水位，每轮尝试数和成功批次数都有上限。若单条变更或基线已超过单批预算，维护可能停滞，daemon 记录告警而不跳过它。失败批次保留最近一次已提交水位，同轮此前成功的批次不会回滚。redb 裁剪事务通过与 Kernel 共用容量的有界阻塞端口执行；进度、滞后、停滞和错误通过日志观察。该政策不保证 redb 文件或进程 RSS 严格有界，也不负责 Source 私有记录、Fact 和 Console 审计的保留。

`[kernel].max_handle_slots` 默认将 daemon 各执行器共享的句柄槽位索引限制为 65,536。空闲和永久退役索引也计入上限；它不限制 Driver 捕获的载荷或总进程内存。

root 初始化先取得不可登录的 `provisioning` 账户归属，再写入凭据，并通过 CAS 激活对应账户实例。中断的初始化可在下次启动接管；旧尝试不能覆盖已接管的实例。已有 active、disabled 或 locked 账户不会被重新初始化。随机密码引导要求 stderr 是交互终端；非交互部署须预先设置 `console.root.password_hash`、`console.root.password` 或 `console.root.pubkeys`。

## MFA Provider 安装

`console.auth.mfa.install_totp = false` 不安装内置实现，也不执行其参数组合校验；配置仍须使用合法字段类型和算法名称。已注册因素及原参数继续保留，移除 provider 不会撤销账户的 MFA 要求；账户中未消费的恢复码仍可使用。

Rust 宿主通过 `ConsoleConfig.auth.mfa.providers` 安装原生实现，TOML 不能加载 provider 代码。宿主在装配时校验并冻结每份声明，发现和注册准入共用该声明。实际安装总数最多 32 个：安装内置 TOTP 时可再安装 31 个扩展，不安装时可安装 32 个。重复的已安装 ID 会使装配失败。关闭内置 TOTP 后，Rust 宿主可在 `totp` ID 下显式安装兼容实现，但必须能识别该 ID 已保存的 verifier。详见[第二因素契约](console-http-and-credentials.md#第二因子与凭据生命周期)。

每份声明将注册 schema（`begin_schema`、`setup_schema`、可选 `pending_schema`）与 `authentication.proof_schema`、`authentication.interaction.challenge_schema` 分开。每轮注册或认证挑战各自携带该轮的响应 schema。缺失的能力不可用，操作之间不隐式借用其他 schema。交互挑战或外部审批需要宿主安装相应原生 provider，daemon TOML 不会安装推送服务。

安装与允许使用分别配置。每个 provider 的使用覆盖项同时约束原生调用和所有 adapter：

```toml
[console.auth.mfa.provider_usage.totp]
allow_enrollment = false
allow_authentication = true
```

该配置停止新注册（包括已有 pending setup 的确认），保留已有 TOTP 认证。每个字段默认 `true`，未配置的 provider 默认允许两种用途。ID 必须符合语法，可以指向当前尚未安装的 provider；配置不安装代码，也不启用 descriptor 未声明的操作。宿主在装配时校验并将使用决定与已安装实现共同固定。

认证允许决定覆盖登录、step-up 的直接证明与每轮交互。策略拒绝保留 continuation，不计入错误凭据次数；取消和因素管理保留原有授权要求，恢复码和 Passkey 主认证独立。关闭使用不轮换 epoch、不改写历史证据，也不降低账户已有的第二证明要求。允许注册但禁止认证的组合有效，不过新因素暂时不能在该宿主认证；发现分别报告能力与使用策略。

以下字段属于 `[console.auth.mfa]`，时间均使用整数毫秒；宿主将数值限制在表中的上下界内：

| 字段 | 默认值 | 生效边界与含义 |
| --- | --- | --- |
| `enrollment_ttl_ms` | `300000` | 待确认注册有效期，30 秒至 15 分钟 |
| `recent_auth_ttl_ms` | `300000` | 凭据管理近期认证窗口，30 秒至 15 分钟 |
| `authentication_ttl_ms` | `120000` | 整个认证 continuation 的有效期，30 秒至 5 分钟，继续不续期 |
| `max_authentication_steps` | `16` | 实际 provider 调用次数，1–32 次，包含认证 begin |
| `max_enrollment_steps` | `16` | 注册 provider 调用次数，2–32 次，包含 begin 与最终验证 |
| `min_poll_interval_ms` | `500` | 最小轮询间隔，100–30000 毫秒；provider 可要求更久等待，但不能超出原期限 |

因素选择和在途 provider 工作共用 challenge ledger 的数量与字节限额。通过当前 provider 使用策略和账户准入检查后，过早轮询只返回剩余等待时间，不调用 provider，也不消费 continuation。在途轮次被取消后仍占用配额，直到该调用结束并回收条目，或原期限到期允许回收；不恢复或重试崩溃的 Future。这些限额约束存储、并发及单个认证的调用次数，不是全局每秒调用预算。每个实例在 claim 共享 continuation 前应用自己的冻结使用策略；遭拒绝的请求可以回到允许的实例继续。全局限制由宿主统一装配配置实现；恢复交互仍须使用与保留 verifier 和私有状态兼容的实现。

## 联邦发布端

联邦 Session 只接受协议版本 1。`Hello.served_capabilities` 是有限位图，v1 会话
transcript 同时认证版本与位图。它公布提供的服务组，不是调用者授权或 TLS 证据：
`Publication = 1`、`Invoke = 2`、`Object = 4`、`Snapshot = 8`。普通客户端连接不公布
任何服务组。宿主按操作选择兼容的已认证 peer Session，不能任取一个活动连接。
共享传输拥有权见 [API 参考](api-reference.md)。

stock daemon 在显式设置 `server.federation_grpc_addr` 后接受入站联邦 Session，也可不开放监听而主动建立出站 Session。它要求显式选择 `federation-grpc` 编译 feature、redb 存储、由本地 ML-DSA-65 根授权的在线签名密钥，以及 daemon 自己持有的 `production_tls` 或 `mtls`。默认构建不包含联邦；显式联邦 feature 不启用通用持久执行。明文、代理信任、TLS 恢复和经典算法降级均会拒绝。TLS 证书与联邦身份根分别配置；每个业务请求都会按已验明的根和在线授权复查持久 peer 政策。

```toml
[storage]
kind = "redb"
path = "xolotl.db"
state_history = "full"

[server]
federation_grpc_addr = "127.0.0.1:9446"

[federation]
root_descriptor_path = "/etc/xolotl/federation/root.bin"
online_key_path = "/etc/xolotl/federation/online.pk8"
online_authorization_path = "/etc/xolotl/federation/online-authorization.bin"
online_authorization_signature_path = "/etc/xolotl/federation/online-authorization.sig"

[[federation.peers]]
node_id = "<对端根节点 ID 的 96 位十六进制>"
enabled = true
minimum_online_generation = 1
allowed_authorization_digests = ["<规范在线授权字节的 SHA-384，96 位十六进制>"]

[[federation.peers.exports]]
name = "notes"
serve = true
receive = false

[[federation.streams]]
id = "<稳定 stream ID 的 32 位十六进制>"
export = "notes"

[[federation.state_history_publications]]
prefix = "state://federation/public/notes"
stream_id = "<与上方相同的 32 位十六进制>"

# 可选：允许任意已认证的联邦节点读取这一条精确 stream。
[[federation.public_streams]]
stream_id = "<与上方相同的 32 位十六进制>"
enabled = true
max_read_records = 8
max_read_bytes = 524288

[federation.grpc.transport_security]
mode = "production_tls"
certificate_chain_path = "/etc/xolotl/federation/tls-cert.pem"
private_key_path = "/etc/xolotl/federation/tls-key.pem"
```

四个联邦身份文件为二进制格式，必须使用绝对路径、权限 0600 的普通文件，不接受符号链接。`root.bin` 为 `FederationRoot::encode()`，`online.pk8` 为 `FederationOnlineKey::to_pkcs8()`，授权文件为 `FederationOnlineKeyAuthorization::encode()`；签名文件是根密钥对授权字节按 `OnlineKeyAuthorization` 用途签出的原始签名。根私钥保持离线。对端 node ID 从已验证的根描述取得；在线摘要是其规范授权字节的 SHA-384。`mtls` 还须像 External gRPC 一样设置 `client_trust_roots`。

在保管离线根密钥的 Linux 机器上签发身份：

```sh
cargo run -p xolotl-federation-key -- init-root --out-dir /secure/offline/xolotl-root
cargo run -p xolotl-federation-key -- issue-online --root-dir /secure/offline/xolotl-root --out-dir /secure/offline/online-1 --generation 1 --not-before-ms 1800000000000 --expires-ms 1900000000000
cargo run -p xolotl-federation-key -- inspect --dir /secure/offline/online-1
```

两个输出目录都必须是尚不存在的绝对路径。`init-root` 创建权限 0700 的目录，内含 `root.pk8` 和 `root.bin`；`issue-online` 读取并核对两者，再创建单独的 0700 目录，仅含上述四个供 daemon 使用的 0600 文件。工具不会把 `root.pk8` 放进在线目录，也不会覆盖已有路径。只将四文件在线目录转移到 daemon 主机的新私有目录，并把四个配置路径改为实际位置；`root.pk8` 留在离线环境。`not-before-ms` 是包含端点，`expires-ms` 是排除端点，均为 Unix 毫秒时间戳；应选择当前有效的时间区间与递增的 generation。`inspect` 验证根签名及在线私钥匹配，按 `key=value` 行输出 `node_id`、`authorization_sha384`、代次与有效期。对端配置使用输出的 `node_id`，并把 `authorization_sha384` 放入 `allowed_authorization_digests`；`inspect` 不替对端的本地准入策略做决定。

daemon 在绑定端口前把 peer 启用状态、精确在线摘要、最低代次与 export 权限存入同一个 redb 文件；默认没有可信 peer。修改已有政策时，peer/export 使用当前持久修订作为 `expected_revision`，在线准入使用 `admission_expected_revision`；旧修订会拒绝启动。首次新增的启用 peer 先以禁用状态建立，安装其他规则后才启用，因此其 peer 修订从 2 开始。配置中删除 peer 条目会在下次启动时禁用该 peer；删除 export 条目会禁用其已持久化的两个方向，旧配置不能凭旧修订重新授权。也可设置 `enabled = false` 或清空摘要列表撤权。最低在线代次不可降低。

联邦资源调用需要精确的方法 manifest 和独立授权。程序仅在当前宿主内执行，不提供重启续跑。程序文件必须是绝对路径、权限 0600、非符号链接的 JSON `Program`；`{"version":1,"body":{"kind":"input"}}` 是最小的字节回显程序。stock 加载器拒绝原生 `Module` 导入；嵌入宿主可提供本轮步骤目录。`program_id` 是 `Program::from_json(file)?.compile()?.id()`；`contract_digest` 是 stock 加载器对导出名、路径、方法、编译程序 ID、稳定的 `identity://` acting 路径、codec 和规范化请求 grant 所算的 BLAKE3 摘要，算法见[代码](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-daemon/src/federation_catalog.rs)。配置摘要不匹配时，加载器会报告实际计算值，供操作者审查后固定两项承诺。任一绑定内容变化都须换摘要；启动时两项承诺必须匹配。既有业务结果保持原 codec 合同；未知工作不重新执行。`bytes_v1` 收发原始字节；其他结果类型需要嵌入宿主提供 codec 和目录。

```toml
[[federation.methods]]
export = "tools"
path = "/echo"
method = "echo"
program_path = "/etc/xolotl/federation/echo.json"
program_id = "<编译后的 portable 程序 ID，64 位十六进制>"
contract_digest = "<绑定方法合同的 64 位十六进制摘要>"
identity_path = "identity://federation/echo"
codec = "bytes_v1"

[[federation.methods.grants]]
selector = "perform://effect/echo"
methods = ["invoke"]
flags = []

[[federation.call_authorities]]
presenter = "<对端认证 node ID，96 位十六进制>"
subject = { kind = "node" }
export = "tools"
path = "/echo"
method = "echo"
contract_digest = "<与方法相同的 64 位十六进制摘要>"
enabled = true
expires_ms = 1900000000000
max_input_bytes = 65536
max_prepare_window_ms = 30000
max_result_retention_ms = 86400000
```

对端还须获授 `tools` export 的 `serve = true`。声明方法本身不授予访问权限。每条调用授权绑定一个 presenter、主体和精确目标，并有独立期限和限额；修改已有条目须填写 `expected_revision`。删除条目会在监听前停用其持久记录。Prepare 在分配 CallRef 前同时检查当前授权与可执行目录；Invoke 和取消经过 Kernel 桥。主动拨出的 Session 也能沿同一桥接受反向调用。持久调用记录保存业务请求／结果证据，而非可重启的执行状态。已受理但没有终态结果的工作在重启后保持未知，不得重放未知效果。

调用节点可把对端方法映射为本地 Kernel effect，并为该 peer 配置固定拨号路由：

```toml
[[federation.outbound_calls]]
local_path = "effect://federation/peer-echo"
local_method = "invoke"
binding_generation = 1
peer_node = "<目标节点 ID，96 位十六进制>"
export = "tools"
path = "/echo"
method = "echo"
contract_digest = "<与目标方法相同的 64 位十六进制摘要>"
allowed_acting = ["root"]
codec = "bytes_v1"
```

调用者仍需本地 Kernel grant 才能打开并调用该 Resource。`allowed_acting` 列出以节点主体调用的稳定本地 acting 身份，请求体不能自行选择。目标、codec 和 generation 在执行前固定。stock `bytes_v1` 映射与目标端 `bytes_v1` 方法交换原始字节 Value。来源端在同一持久库中保存操作身份域和执行 ID，发送前固定操作对应的目标；重连后沿原 CallRef 查询；重启后可读取业务结果，但已接纳且无终态的工作保持未知，不恢复程序或重发未知副作用。目标端须授予调用节点该 export 的 `serve = true` 和精确的 `call_authorities` 规则。来源收到真实终态收据并完成所属业务责任后，维护可删除调用载荷，保留紧凑的操作标记阻止重放。该标记只覆盖正常重启，不覆盖恢复旧备份；恢复规则见下文。

若要让一个稳定的本地 acting 身份作为 Hosted 主体调用，配置由宿主持有的凭据，并在精确的出站方法绑定中列出它的名称：

```toml
[[federation.outbound_hosted_subjects]]
name = "alice"
acting = "identity://people/alice"
peer_node = "<目标节点 ID，96 位十六进制>"
issuer = "<主体 issuer ID，96 位十六进制>"
namespace = "app"
subject = "alice"
issuer_descriptor_path = "/etc/xolotl/federation/alice-issuer.bin"
assertion_path = "/etc/xolotl/federation/alice-assertion.bin"
issuer_signature_path = "/etc/xolotl/federation/alice-assertion.sig"
holder_key_path = "/etc/xolotl/federation/alice-holder.pk8"

# 在匹配的 [[federation.outbound_calls]] 中添加：
# allowed_hosted = ["alice"]
```

四个凭据文件必须是绝对路径上的非符号链接常规文件，权限为 0600。签发者断言须与声明的 issuer、namespace 和 subject 一致，把本节点绑定为 presenter、目标节点绑定为 audience、用途限定为 `invoke`，并绑定所给持有者公钥。`allowed_hosted` 只允许列出的凭据调用该方法；`allowed_acting` 仍是节点主体清单。目标端还须为该 presenter 配置 `invoke` issuer 策略和 Hosted `call_authorities` 规则。daemon 代持 holder 私钥并逐请求签名；用户自行保管密钥时，嵌入宿主须实现 `FederationCallPrincipal` 和 `FederationCallSessionProvider`。业务调用查询或重连时，Prepare、Inspect 与 Cancel 都从持久调用主体取得相同的 Hosted 上下文。未结算调用期间须继续保有有效 holder 凭据；凭据移除或过期、目标撤销 issuer 授权时，待发取消与终态查询保留待修复，不会降级成节点主体。

Hosted 主体使用 `subject = { kind = "hosted", issuer = "<96 位十六进制>", namespace = "app", subject = "alice" }`，并通过 `[[federation.subject_issuers]]` 显式准许该 issuer、命名空间、presenter 和 `invoke` 用途。仍须提交已验证的签发者断言与持有者逐请求 ML-DSA-65 证明；节点级授权不自动授予 Hosted 主体权限。issuer 规则的 audience 固定为本节点，其他用途为 `discover`、`sync`、`object_read`。

Hosted stream 访问另需精确 grant，并为 presenter 配置 `sync` issuer 规则：

```toml
[[federation.subject_issuers]]
issuer = "<issuer ID，96 位十六进制>"
namespace = "app"
presenter = "<已启用 peer 的 node ID，96 位十六进制>"
purposes = ["sync"]

[[federation.subject_grants]]
issuer = "<同一 issuer ID>"
namespace = "app"
subject = "alice"
presenter = "<同一 peer node ID>"
stream_id = "<本地已声明 stream ID，32 位十六进制>"
not_before_ms = 1800000000000
expires_ms = 1900000000000
history = "from_grant"
enabled = true
# expected_revision = 1  # 修改已有条目时填写当前修订。
```

`history = "all"` 允许读取已有记录；`from_grant` 从授予时已提交的 stream 前沿开始。启用的 stock grant 要求已配置且启用的 peer，以及匹配的 `sync` issuer 规则。创建时不填写 `expected_revision`；修改时必须匹配持久条目的当前修订。省略 `subject_grants` 表示由嵌入宿主管理；在 `[federation]` 下设置 `subject_grants = []` 表示 daemon 持有空 manifest，启动时禁用以前启用的 grant。非空 manifest 也会在提供服务前禁用未列出的条目；未变化的条目保留原修订。

未配置 peer 的节点也可进入 Guest Session，但 `subject_issuers` 必须显式列出精确的 presenter、issuer、命名空间及 `sync` 或 `object_read` 用途。宿主管理的邀请存储随后通过持有者逐请求签名的 `RedeemInvitation` 帧兑换指定接受者或持有者邀请。兑换只为一个 Hosted 主体、presenter 和 stream 创建带邀请来源的 grant；Guest 的 Open/Read/Inspect/Close/Acknowledge 每次都复核此 grant，不建立 peer 权限。邀请撤回或到期阻止新兑换；已兑换 grant 继续有效，直到自身到期或被精确撤销。持有者邀请只能在已按这些规则信任 issuer 与 presenter 的持有者之间转交；stock 宿主尚不支持完全未知 presenter 或 issuer 的开放式持有者邀请。daemon 提供 Session 兑换，并通过 `invitation_issuer_authorities` 和 `invitations` 选择完整的 stock 自有清单。省略清单保留宿主管理行；提供清单只对账 stock 自有行，撤销遗漏项，变更须匹配精确修订。持有者条目只保存预先计算的秘密摘要。

stock 发布来源只把配置的 `state://federation/public/<namespace>` 前缀下、无 taint 的 State 历史变更复制到对应 stream，记录类型为 `xolotl.state.mutation.v1`，载荷是 JSON。必须启用 `state_history = "full"`，但不要求永久保留未经裁剪的历史。每轮共用一个已提交高水位，沿提交时间索引轮转有界页面；tick 最多接纳八个存储作业，完成的前缀退出队列，阻塞作业的 AtCapacity 保留进度。发布身份配额拒绝且尚无收据时，保留该页面并轮转其他 pending publisher，让它们用原已接受身份结算返额。完整轮转仍无发布进展时返回 Capacity，不忙等或删除证据。启动完成初始轮次后才创建 FromGrant 邀请或发布 ready。

页面在追加前持久化固定 high、exclusive continuation 和原生 retry epoch。结算在同一事务中校验精确收据、关闭 epoch、仅回收已确认身份，并推进源历史 pin。追加一部分事件后遇到确定的身份配额拒绝，可结算已确认的连续前缀并返还配额，不要求并发 publisher 都先完成整页。未结算事件继续受 pin 保护，且结算必须确认这些事件在该 epoch 没有已接受身份。未知尝试保留原窗口与 epoch；数据库提交不确定时先释放数据库用户并重开，再核对持久窗口。这是业务复制状态，不是跨重启执行。

最多 64 个 publisher 持有持久 pin，每行最多包含 4 MiB continuation 加 16 KiB 元数据；裁剪最多扫描 64 行，解码失败时拒绝删除。注册与裁剪在同一写事务锁内检查当前 floor；新 publisher 不能重建缺失历史。移除配置保留 pin。可信宿主须先结清 pending page，再以精确前缀与完整完成的 cursor 调用 `release_publication`；未决或未知页面不能过期或释放。已释放的 stream 不能重新注册为完整前缀 publisher；新 stream 要求初始历史完整。每条 stream 对应一个不重叠的发布前缀，规范 UTF-8 路径最多 4096 字节，其他 State 路径不会自动发布。公开暴露政策要求监听器；本地发布和显式退役可以不开放监听。stock 单条记录最大 512 KiB；`federation.grpc.max_batch_bytes` 至少为 512 KiB，`max_frame_bytes` 至少为 516 KiB。应限制发布命名空间以控制首次扫描工作量。

退役 State 发布者时，移除其活动 `state_history_publications` 条目，显式声明精确的最终游标：

```toml
[[federation.state_history_publication_retirements]]
stream_id = "<现有本地 stream 的 32 位十六进制 ID>"
prefix = "state://federation/public/notes"
expected_cursor = 1800000000000 # 精确的完成游标，或已保存窗口的 pending high
```

最多接受 64 个不同 stream 的退役声明，同一 stream 不能仍有活动 State 来源。可以保留 `streams` 声明及访问／副本政策，继续提供已有记录。退役要求 redb、完整 State 历史能力和现有联邦身份／安全配置，不要求监听器。启动在声明 stream 或绑定监听之前核对已有 pin。`expected_cursor` 须匹配无待定窗口的完成游标，或已保存窗口的精确 high。原生只读 `publication_status` 端口提供两项值；失配错误报告实际值，不创建工作。前缀错误、未知 stream、容量失败或提交不确定使启动失败，不免除责任。

daemon 使用原追加身份及有界存储 worker，只结算已保存窗口，再条件释放显式退役的 pin。结算前校验全部退役声明，并将已配置活动 publisher 的既有 pending 窗口纳入同一公平轮转，让其已接受身份有机会结算、返还共享额度。各窗口保持各自已保存的 high；恢复不创建新窗口，也不发布后续 State 变更。完整轮转仍无进展时拒绝启动。已有记录、副本承诺和访问政策各有拥有者；移除其配置仍遵守各自政策。释放跨重开保持，原 stream 不能重新注册为完整前缀 publisher。可保留已执行的退役声明；pin 缺失报告为缺失，不证明所给前缀或游标曾被发布。仅移除配置仍保留 pin。每页结算和释放分别提交；启动失败或取消不撤销此前确认的结算／释放，未知结果须先重开存储拥有者再对账。

State 路径中的 `public` 片段本身不授予网络读取权限。未配置 `[[federation.public_streams]]` 时，读取者必须是已配置的 peer 且获授对应 export 的 `serve` 权限，或持有精确的邀请来源 Guest grant。公开 stream 策略向通过 TLS 通道绑定的根与在线密钥证明的节点开放无状态 `InspectPublic`、`ReadPublic`；这些读取不会在发布端创建 peer 或 subscription 记录。未知节点还可凭精确 node-self 对象授权使用 `ReadObject`，或使用上文限定的 Guest 操作。被明确禁用的 peer 不能降级为公开或 Guest 访问。首次启用公开策略必须在 stream 为空时完成，因此 daemon 会在扫描 State history 之前提交策略。修改策略须填写当前持久 `expected_revision`；删除配置条目会禁用该策略。已禁用的 stream ID 不可再次公开，需要换新的 stream ID。`max_read_records` 必须为正且不超过 256，`max_read_bytes` 必须为正且不超过 4 MiB，并符合已配置的 gRPC 批次上限。公开分页按策略修订校验，每次请求都重查撤权。仅配置公开流的发布端需要监听，但不必配置 `[[federation.peers]]`。

对象授权与 stream、peer export 权限相互独立。宿主在签发持久授权前验证对象确实存在；`ReadObject` 请求重复完整内容身份、授权 ID 和修订。接收方跨分块请求和新 Session 保持同一非零 16 字节传输 ID，校验完整对象的 SHA-384 后才提交。PublicOnly 节点只可使用 node-self 授权；Guest 可在注册 `object_read` 用途明确信任的 issuer 后使用精确 Hosted 对象授权；已配置的私有 peer 可使用这两类精确授权。每个分块读取前后都会复查撤权、期限、范围和披露字节预算。

```toml
[[federation.object_grants]]
presenter = "<读取节点 ID 的 96 位十六进制>"
subject = { kind = "node" }
hash = "<对象 SHA-384 的 96 位小写十六进制>"
size = 1048576
mime = "application/octet-stream"
range_start = 0
range_end = 1048576
expires_at_ms = 1900000000000
max_total_bytes = 4194304
max_chunk_bytes = 262144
```

授权仅覆盖这一精确对象及半开字节范围。`max_total_bytes` 包含重试，必须覆盖所授范围；`max_chunk_bytes` 不得超过 1 MiB，还须符合 gRPC 批次和帧上限。首次启动会分配持久授权 ID，并写入日志供接收方使用。相同 manifest 在重启后复用已有授权；删除条目会在监听前撤销它。已撤销的授权不能由旧 manifest 重新签发。完全省略 `object_grants` 时，嵌入宿主管理的授权保持不变；配置空列表会撤销该 manifest 管理的全部旧授权。

已启用且配有固定拨号路由的私有 peer 可以把精确授权对象取回本地对象存储：

```toml
[[federation.object_receives]]
provider_node = "<提供节点 ID，96 位十六进制>"
grant_id = 1
grant_revision = 1
hash = "<对象 SHA-384 的 96 位小写十六进制>"
size = 1048576
mime = "application/octet-stream"
owner_digest = "<本地事件或结果归属的 96 位十六进制摘要>"
max_chunk_bytes = 262144
```

提供方授权须允许本节点以节点主体读取。stock 接收最多配置 64 项，每个对象不超过 64 MiB，最多同时下载两项；分块不超过 512 KiB 或传输批次上限。接收方持久保存稳定传输 ID，校验完整对象后只记录 `Verified`；应用持久发布自身引用后，才能把收据标为 `Bound`。Hosted 接收主体和应用引用绑定需要嵌入宿主。

只主动拨号的节点可省略 `server.federation_grpc_addr`，在已授权 peer 下配置固定出站路由：

```toml
[[federation.peers.subscriptions]]
stream_id = "<对端 stream ID 的 32 位十六进制字符串>"
generation = 0
# 仅对应用可归档的快照 schema 显式启用。
# snapshot_schema_revisions = ["<64 位十六进制 schema 修订>"]

[federation.peers.dial]
uri = "http://peer.example:9446"
server_name = "peer.example"
trust_root_path = "/etc/xolotl/federation/peer-ca.pem"
```

URI 是 h2 地址，连接器仍强制使用完整握手的混合 TLS，并同时固定 TLS 信任根及已签名的联邦 node ID。订阅所用 export 必须有 `receive = true`。daemon 将记录验收进 redb inbox，只有验收后才确认；断线后以新的 TLS 绑定 Session 和稳定 Open 身份重连。授权变更后若要建立新的持久交付约定，应递增订阅的 `generation`。提供监听的节点也可以只配置 `[[federation.peers.subscriptions]]`，复用对端拨入的 Session 反向读取其 stream，因此对端无需监听。同一 Session 双向承载请求。

快照 offer 全部为 `action = "retire"` 时既不要求监听，也不要求拨号路径；退休在本地
结清保留责任，无须网络访问。任何 `action = "publish"` 仍要求网络路径（监听或拨号）
及兼容服务组。这一区分针对快照 offer，不扩大为全部本地 State-history 发布的要求。

私有 node-self 订阅遇到历史缺口时，只有配置了可接纳的 `snapshot_schema_revisions`（最多 16 个），且发布端为精确订阅提供快照，stock 才会归档；空列表使缺口明确失败。应用或操作员必须证明内容覆盖精确的已提交位置，且不含被排除的历史；daemon 核对文件摘要、大小、日志位置与当前权威，但不能从字节推断应用语义，也不会安装应用投影。发布端显式声明此证明：

```toml
[[federation.snapshot_offers]]
action = "publish"
subscriber_node = "<接收节点 ID，96 位十六进制>"
stream_id = "<本地 stream ID，32 位十六进制>"
subscription_generation = 0
snapshot_id = "<应用不重复使用的快照 ID，32 位十六进制>"
position_sequence = 42
position_digest = "<覆盖记录的摘要，96 位十六进制>"
schema_revision = "<应用快照 schema 修订，64 位十六进制>"
content_path = "/var/lib/xolotl/sealed/snapshot.bin"
content_digest = "<完整内容 SHA-384，96 位十六进制>"
content_bytes = 1048576
publication_digest = "<应用持久发布证明的摘要，96 位十六进制>"
```

stock 在披露前将每份最多 64 MiB 的内容复制并校验到私有发布 pin；最多声明 64 项 offer，保留 64 个 pin 文件。精确私有 Open 建立后才发布 offer，反向 Session 也支持；其日志 pin 保留到显式退休。退休时将条目改为 `action = "retire"`，只保留 `subscriber_node`、`stream_id`、`subscription_generation`。删除条目不会擅自退休持久 offer。接收端把有界分块写入 `[storage].path` 旁的独立私有归档，完整校验并同步后只提交 `Archived` 交付基线；重启复核字节，随后可有界接纳快照后的 inbox 记录。该基线不是应用投影。嵌入宿主须先持久安装应用状态，并把完成凭据绑定到同一安装 ID，才能报告投影进度或清理旧 inbox 代次。应用确认旧代次的读者和任务均已停止后，才可为形成的 `Projected` 锚点声明释放：

归档收据绑定精确 subscription、install/archive digest 与非零 Federation generation。连续 suffix 持久接受后，接收方从归档基线或上次确认的 suffix 前沿发送原生 coverage，并携带 through position 的精确 digest；发布方逐条校验有界页面内新增覆盖的日志记录后，才推进 replica snapshot coverage。缺口、旧 generation 或不匹配收据均拒绝。Archived 的普通事件 ACK 始终为空：coverage 不声称缺失前缀事件已接受，不安装应用状态；排队收据仍在最终交付时复核权限。

```toml
[[federation.snapshot_reader_releases]]
publisher_node = "<发布节点 ID，96 位十六进制>"
stream_id = "<其 stream ID，32 位十六进制>"
subscription_generation = 0
install_id = "<当前安装 ID，32 位十六进制>"
federation_generation = 1
application_generation = 1
completion_digest = "<当前完成证明摘要，96 位十六进制>"
release_digest = "<应用持久读者释放决定的摘要，96 位十六进制>"
```

stock 要求非零应用代次与联邦代次相等，并以推导出的订阅核对持久 `Projected` 锚点、精确安装 ID 和完成摘要。只有 `Archived` 时声明释放会被拒绝；stock 不会自行生成应用完成凭据。有效释放在 peer 被移除或本地接收者关闭后仍可保留；清理分批删除旧 inbox 行，每次最多清理四个旧归档文件。`release_digest` 记录可信应用或操作方的持久决定，并不能以密码学方式证明读者确已停止。清理跨重启进行时保留这项声明。未声明则旧代次继续保留；`.part` 与封存文件合计最多 64 个。公开和 Guest 关注不使用该私有快照合同。

私有副本的发布侧留存是一项独立承诺。配置接收者的精确节点 ID，以及与它的 `[[federation.peers.subscriptions]]` 相同的 `generation`；嵌入宿主也可提供精确的 16 字节 `subscription_id`。启用条目只能二选一：

```toml
[[federation.replica_members]]
stream_id = "<本地 stream ID，32 位十六进制>"
member_node = "<接收节点 ID，96 位十六进制>"
stock_generation = 0
enabled = true
# lease_until_ms = 1900000000000  # 不填即永久承诺。

[federation.replica_history_maintenance]
stream_ids = ["<本地 stream ID，32 位十六进制>"]
interval_ms = 10000
max_batches_per_tick = 8
records_per_batch = 256
```

发布端等该节点的存活 node-self 订阅 Open 后才加入成员；之前 stock 自动裁剪跳过相应流。加入时所需历史仍须可读。普通订阅或 ACK 不会自动建立复制承诺。省略成员条目不会退休已有承诺；要退休，配置仅含 `stream_id`、`member_node`、`enabled = false` 及当前 `expected_revision` 的禁用条目，daemon 在提供服务前提交退休。延长或重新加入同样需要当前修订；重新加入必须换新订阅 ID，通常通过增加接收方的 `generation`。租约最长 30 天，daemon 不会暗中续期；期限过后由有界留存事务持久提交到期。已到期租约的启用条目不会恢复承诺。

发布日志自动裁剪按本地流显式启用。最多选择 64 条流，每轮全局预算为八笔轮转事务，每笔最多 256 条记录及 64 MiB 载荷；`interval_ms` 允许 1 秒至 1 天。每流最多 64 名成员，配置总量最多 1024 项。redb 在同一事务内核对全部活动承诺、发布端已确认 ACK 和快照 pin，再删除连续前缀。有成员等待 Open 时，stock 自动裁剪暂停该流；错误停止当轮尝试并记录，重启不会推断 ACK 或暗自退休成员。应用投影和接收 inbox 的留存另行决定。

只关注陌生节点明确公开的流时，可以使用独立的公开 follower；它不在发布方创建私有 peer 或 subscription。此节点可以只主动拨号，不开放联邦监听：

```toml
[[federation.public_follows]]
publisher_node = "<发布者根节点 ID，96 位十六进制>"
stream_id = "<公开 stream ID，32 位十六进制>"
minimum_online_generation = 1
allowed_authorization_digests = ["<发布者规范在线授权的 SHA-384，96 位十六进制>"]
max_inbox_records = 1024
max_inbox_bytes = 8388608

[federation.public_follows.dial]
uri = "http://public.example:9446"
server_name = "public.example"
trust_root_path = "/etc/xolotl/federation/public-ca.pem"
```

每条规则固定发布者根身份、在线授权摘要、TLS 信任根与精确 stream；同一发布者不能同时有私有 peer 行，已禁用的持久 peer 行也不能绕过此限制。最多配置 64 条公开关注。每条本地 redb inbox 的 `max_inbox_records` 为 1–4096，`max_inbox_bytes` 为 512 KiB–64 MiB，且须至少容纳配置的 gRPC 批次。follower 重连后从持久摘要位置继续读取，并在同一事务内接纳新页和裁剪最旧的本地记录；该滚动 inbox 不承诺应用已投影的数据永不丢失，也不构成发布者的复制保留义务。发布者历史已越过游标时返回 `ResyncRequired`，目前没有快照原子重同步。应用需要自行读取和投影本地 inbox，并定义缺口处理。

邀请限定的 Guest follower 可使用受明确信任的 Hosted 主体，不在发布方创建私有 peer 行。发布方须先允许对应签发方、呈现节点的 `sync` 用途，并签发精确邀请。下例使用指定主体邀请；bearer 邀请另设 `invitation_secret_path`，指向保存原始 32 字节秘密的私有文件。

```toml
[[federation.guest_follows]]
publisher_node = "<发布者根节点 ID，96 位十六进制>"
stream_id = "<受邀请流 ID，32 位十六进制>"
minimum_online_generation = 1
allowed_authorization_digests = ["<发布者在线授权 SHA-384，96 位十六进制>"]
generation = 1
invitation_id = "<邀请 ID，32 位十六进制>"
invitation_revision = 1
issuer = "<Hosted 签发方 ID，96 位十六进制>"
namespace = "app"
subject = "visitor"
issuer_descriptor_path = "/etc/xolotl/federation/guest-issuer.bin"
assertion_path = "/etc/xolotl/federation/guest-assertion.bin"
issuer_signature_path = "/etc/xolotl/federation/guest-assertion.sig"
holder_key_path = "/etc/xolotl/federation/guest-holder.pk8"
max_inbox_records = 1024
max_inbox_bytes = 8388608

[federation.guest_follows.dial]
uri = "http://friend.example:9446"
server_name = "friend.example"
trust_root_path = "/etc/xolotl/federation/friend-ca.pem"
```

断言的 presenter 必须是本地节点、audience 必须是固定的发布者、用途必须为 `sync`；daemon 启动时验证签发方签名及 holder 密钥。最多配置 64 条 Guest 关注，本地 inbox 限额与公开关注相同。follower 持久保存邀请兑换、Open、已接纳页及滚动 inbox；重连后只对持久接纳的位置重发 ACK。替换本地关系时递增 `generation`。撤权阻止新读取，历史缺口仍返回 `ResyncRequired`；该 inbox 不代表应用投影完成，也不承担复制保留义务。

远端存储将已验证在线证明与宿主决策时钟带入实际本地授权决定，在同一锁／事务核对当前 peer／密钥政策和业务记录。排队后的 Kernel 准入及资源调用、暂存对象披露、快照提交和接收方接纳均重新核对。公开与访客关注保留发布者固定政策并拒绝已配置 peer 行。撤销约束新的本地决定，不撤回已准入的物理 Driver 效果，也不创建跨库或跨节点共同事务。

联邦 redb、在线授权、对象及密钥备份须作为同一恢复代次管理。stock daemon 没有库外可信高水位；将旧 redb 备份恢复到原联邦身份后直接联网，可能复用发布序号和出站调用身份，也可能丢失撤权与去重墓碑。旧备份必须先隔离并对账，再以新的联邦根、流和订阅身份重新配对。待处理的未知调用须隔离至外部效果完成对账；仅更换身份不足以安全重放。正常崩溃后重开同一个未回滚数据库不属于这种恢复。

## 带来源缺席存储

`[storage].absence_record_limit` 与 `absence_encoded_byte_limit` 在内存和 redb 均默认 65536、67108864。各自接受非负整数或显式 TOML 字符串 `"unlimited"`，零禁止新增计量。它们计量留存的带来源缺席记录及后端编码加键，不限制当前值、历史或 RSS。降低额度保留证据并允许非增长提交；redb 要求已初始化的留存计数，元数据缺失即拒绝。

## External Gateway

daemon 的两个传输共享总计 256 个 External 活动会话的生命周期作用域。External gRPC 限制消息解码 1 MiB、首帧 10 秒、空闲 300 秒；WebSocket 保留有界可配置传输限额，同时计入总作用域。先关闭服务准入，再停止监听器并等待作用域终止，最后等待阻塞存储任务，见 [External Gateway](external-gateway.md)。

External gRPC 和 external WebSocket 提供同一套 Provider/Source session 协议：

```toml
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway]
source_command_limit = 65536

[external_gateway.source_maintenance]
interval_ms = 10000
max_batches_per_tick = 64

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

`[storage].source_stream_limit` 限制内建存储在所有安装和投影上的活动有序 Source 流位置，默认 4096，可设为 1–65536。显式 Open 在第一帧事件之前占用名额并签发流代次；事件帧不能创建位置。满额确定拒绝 Open，不改变 sink 或私有事件决策，已有流仍可推进。Retire 在同一提交域关闭指定代次并立即返额；scope 退休遗留的位置由有界维护回收。redb 计数随变更持久化；降低配置额度不会删除现有位置，新 Open 须等占用降至新上限以下。长期活动 scope 可以反复打开、退休同名流而不积累活动位置；事件决策与 State 历史仍有独立的驻留边界。

`[storage].source_retention_limit` 限制内建 memory／redb 存储拥有者保留的 Source 事件决定／凭据对与速率行总数，包含已退休 scope，默认 65536，须为正数。每对决定与凭据、每行速率记录各占一个单位。Duplicate 不新增单位；过期决定替换或已有速率行更新复用原单位。增长型提交超限时原子拒绝并返回 `retention_capacity_exceeded`，不提前驱逐有效证据、不消耗序号。维护删除到期决定／凭据或闲置速率行时返额。降低重开额度保留旧记录，并允许不增加单位的提交。流位置、安装目录、State 值与历史分别管理。记录数与单行边界不等于进程 RSS 或数据库物理文件大小；应按负载同时选择额度、去重窗口和维护吞吐。

`[storage].federation_publish_id_limit` 限制内置 Federation store 全部 stream 保留的已接受发布身份，默认 65536，必须为正。满额时新身份在修改 stream 或日志前以 `Capacity` 拒绝。PublishRequest 绑定显式 per-stream retry epoch；关闭 epoch 后，旧追加请求（包括已知 ID）在执行前永久拒绝，但仍可检查保留证据。只有已关闭 epoch 的精确已确认收据可以授权回收身份并返还配额，未知身份继续计费。裁剪日志正文不返还身份配额；活动 epoch 中已裁剪记录的重试仍返回 `Indeterminate`。重开时降低上限不删除证据。stock State 页面提交将关闭固定 epoch、回收已确认页面 ID 与推进发布 cursor 放在同一事务，正常长期发布可复用配额。新 head 或新页面不会把旧未知尝试升级到新 epoch。此上限不是载荷、RSS 或物理文件上限。

`[external_gateway].source_command_limit` 是共享内存 Source 命令登记器的正数全局容量，不是每个传输各自的配置。默认 65536，合计计费 gRPC 与 WebSocket 的待决命令、留存终态 ID 和按 installation/projection 维护的限速行。待决命令预留其最终终态 ID 的槽位；新增限速行另占一个单位。满额时在发送和消耗速率额度前拒绝派发，不驱逐有效且未过期的 ID。它只限制单位数，不限制字节或进程 RSS，与 Source 事件存储额度独立。

`source_dedupe_window_ms` 限制 Source event ID 的去重保留窗口。Source 命令登记器也用归一化后的值在结果、期限或会话关闭后阻挡同一命令 ID。daemon 零配置取既有默认值，不禁用去重。嵌入宿主可传入零 `SourceCommandRegister::idempotency_window_ms`，在命令转为终态时释放 ID；限速行有独立寿命，保留至自身速率窗口到期。

命令登记执行有界到期清理，周期 Source 维护也清理共享命令 hub，即使它空闲或没有连接。每批沿内存游标最多检查 64 条 ID 与限速行；未回收的过期行继续计费。`SourceCommandMaintenanceReport` 区分已检查、已释放和本轮完成；零释放不表示完成。最早到期提示尚未到达时不遍历，不保留逐 ID 到期索引。命令元数据只属于当前宿主生命周期。维护预算控制到期后的回收速度，不缩短有效去重窗口。

`source_maintenance` 在 daemon 启动时运行一次，此后即使没有 Source session 连接，也每隔 `interval_ms` 运行。命令 registry 清理与 Source 私有事件决策、速率行及已退休 scope 的流位置共享全局 `max_batches_per_tick` 预算。有工作时轮流推进，轮转位置跨 tick 保留，预算为一也不能饿死任一拥有者；已完成者让出剩余预算。每个计费批次最多检查 64 行，使用同一 tick 时间，批次之间释放 hub 锁并让出调度。后端游标跨轮次续扫，redb 重启后仍保留，到达末尾后重置。默认间隔为 10 秒、预算为 64 批。零值使用默认值；超过一小时或 1024 批的值会被截断。每个接受事件的到期时间在提交时由本次传输的有界 `source_dedupe_window_ms` 固定；变更配置只影响新接受的事件，维护不会用当前配置重新解释已有期限。维护删除所有安装和投影中过期的接受决策及对应凭据，即使它们已经卸载；原子提交路径不创建 Pending，未知结果可尽快用相同 event ID 和 payload 重试；有序事件还须保持同一 stream ID、序号和活动流代次。流仍活动、旧决策在后端判定点仍保留时才能得到 Duplicate。已退休流的旧事件在去重前被拒绝，受权证据检查仍可调查保留的决定。重试不通过释放待定预留重放，过期也不证明前次中止。速率记录在最后一次接受的命中离开该行保存的窗口后删除。窗口改变会在下一次接受时开启新的计数期，可能短时放宽；仅改变事件上限会立即针对保留命中生效。活动流位置不按时间删除；scope 退休阻断提交后，维护删除其旧位置并返额，逐流 Retire 则立即关闭活动位置。扫描期间在游标之前新增的行会在下一轮回绕后访问；持续写入快于维护时，单轮预算不能限制总驻留。事件决策和 State 历史仍有独立的保留责任。

`provider_max_in_flight_invocations`、`provider_max_in_flight_per_identity` 和 `provider_max_in_flight_per_effect` 限制每个 ready Provider session 的 pending invoke。`provider_max_inline_result_bytes` 限制 Provider 成功和错误结果的 inline 大小。

`source_max_in_flight_commands`、`source_command_rate_limit_window_ms` 和 `source_command_rate_limit_max` 配置 Source 命令派发限额，`source_command_max_inline_result_bytes` 限制 inline 结果。projection 必须声明命令并进入 Ready，且由受权 Kernel Operation 调用，这些限额才会参与派发。 速率准入不承诺持续吞吐：共享容量与去重窗口须共同容纳窗口内累计新 ID、待决命令和限速行；维护预算控制到期后的返额速度，不允许驱逐有效 ID。

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

External gRPC 支持 `production_tls`、`mtls`、`trusted_reverse_proxy`、`local_trusted`、`unsafe_plaintext` 和 `disabled_for_test`。`production_tls` 要求 `certificate_chain_path` 和 `private_key_path`；`mtls` 还要求 `client_trust_roots`。daemon 的 TLS 模式只接受 TLS 1.3、`X25519MLKEM768`、AES-256-GCM 或 ChaCha20-Poly1305，以及 ML-DSA-65 证书链；会话票据和 0-RTT 已关闭。`trusted_reverse_proxy` 必须配置 `trusted_proxy_peers`；只有直连 peer 命中可信代理时才采信 forwarded header。代理的 TLS 政策由该部署自行执行，daemon 不能代其验证。

`private_key_path` 必须是绝对路径，指向不超过 64 KiB、无 group/other 权限的普通文件。daemon 拒绝路径末端的软链接，监听器配置释放时清零内存中的 PEM 缓冲；父目录和备份仍须独立保护。

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

daemon 的控制台监听器当前是明文监听器。`local_trusted` 只用于 loopback `console_addr`；如果 TLS 由可信前置代理终止，使用 `trusted_reverse_proxy`，并在 `trusted_proxy_peers` 中列出直连代理地址。除非控制台监听器配置了 daemon 持有的 TLS 材料，否则 `production_tls` 会拒绝启动。

Console 仅在 socket peer 可信且启用 `honor_x_forwarded_for` 时采信来源头；否则忽略 `X-Forwarded-For` 和 `X-Real-IP`，使用 socket peer。可信代理列表也用于识别转发链中的代理跳：

- 多个 `X-Forwarded-For` 头值按 header 顺序组成一条链，从右向左跳过可信代理 IP，取遇到的第一个不可信 IP。全部可信时取最左侧 IP；更早的客户端自填值不能覆盖这个来源。
- 扫描可信后缀时遇到空项、畸形值或非 IP 项，回退 socket peer，不再尝试 `X-Real-IP`。只有完全没有 `X-Forwarded-For` 时才考虑 `X-Real-IP`，且它必须是单个 IP 地址；重复 header 或含逗号的值不会被采信。接受的 IP 使用规范化文本参与审计和限额。使用 `X-Real-IP` 后备的代理必须覆盖或移除客户端传入值；单个合法 IP 不能证明其来源。
- 可信且已启用的 `X-Forwarded-Host` 和 `X-Forwarded-Proto` 各自只能有一个 header 值，不能含逗号；重复或组合值会导致 Origin 准入被拒绝。可信代理必须覆盖客户端传入的这两个头，不采用追加方式。不可信或未启用的转发头不覆盖请求 host 或 scheme 检查。

## 运行时配置

Terminal 安装要求宿主拥有的共享 runtime，而不是调用者审批标志或 `high_risk`
伪审批配置。daemon 的宿主装配拥有命令生命周期；嵌入式宿主显式安装拥有者。
容量、拒绝和排空统一见[终端安装](api-reference.md#终端安装)。标准 Fetch 不提供
隐式环境代理或内部网络模式；这类部署使用宿主自定义 Driver，遵守
[驱动边界](security-and-boundaries.md#驱动边界)。

嵌入式 Rust 宿主通过 `ExecutionConfig` 配置 Executor，与 `xolotl.toml` 分开。三张留存缓存 `max_method_metadata`、`max_resource_bindings` 和 `max_method_bindings` 默认各限 4096 项。新增键的规范路径 UTF-8 字节上限 `max_cache_path_bytes` 默认为 1024，方法名 UTF-8 字节上限 `max_cache_method_name_bytes` 默认为 256；新冻结资源契约的接口 ID 数上限 `max_cache_interfaces` 默认为 64。额度耗尽后，同键命中或替换仍可使用；在已有条目产生后调低限额不会逐出它们。这些是项数与部分留存内容的限制，不是分配器精确字节数、原生句柄或整个 Executor 的内存上限。

嵌入式宿主可通过 `KernelBuilder::with_handle_slot_limit(limit)` 为共享 `HandleTable` 设置槽位额度，独立表也可用 `HandleTable::with_slot_limit(limit)` 构造。默认不设限，零禁止安装句柄。额度计入已分配的槽位索引，包括保留的祖先、可复用空位与代次耗尽后永久退役的索引；复用空位不新增索引。`allocated_slots()` 是单调不减的计费数量，`len()` 只表示当前句柄载荷数。该额度不限制单个句柄持有的原生对象或策略内存。

运行时 Provider 设置、模型路由、组、绑定、进程内 Provider/Source projection 声明、外部 Provider/Source installation 声明和策略管理状态都属于 Xolotl state，并通过 Console HTTP 或 WebSocket action 管理。External projection 是 installation 声明的一部分。External 声明使用 `external.*`，inference 声明使用 `inference.*`，进程内 projection 声明通过 `config.*` 写入 `state://kernel/projections/in-process/<id>`。泛用 `config.*` action 会拒绝已经有专用动作族的管理路径。

`xolotl-standard` Cargo feature 决定哪些进程内实现被编译进宿主二进制。可选进程内 projection 声明位于 `state://kernel/projections/in-process/<id>`。reconcile 状态写在 `state://kernel/projection-status/in-process/<id>`，通过 `projection.in_process.status.*` 读取；状态会区分期望声明版本和当前 active registry 版本。嵌入式宿主还可以用 `StandardConfig::with_modules` 选择实际安装哪些已编译的 standard-core 模块；代码编译进二进制并不等于已经公开为 Resource。

HTTP inference provider 只有在宿主二进制启用对应 `xolotl-standard` feature 时才会编译。运行时声明放在 `state://kernel/inference/*` 和 `state://kernel/routing/inference`；backend 记录只保存 `state://vault/inference/<backend>/api_key` 这类 secret 引用，不保存原始 API key。

每个标准 `fetch` 或 HTTP 推理客户端都显式选择受限的后量子 rustls provider，单独启用某个 Provider feature 时也一样。客户端构造不安装也不依赖进程默认 provider；内嵌宿主使用这些客户端时遵守同一政策。使用经典证书链或不支持混合交换的公网 HTTPS 服务因此可能无法访问；这些客户端不会静默退回经典 TLS。宿主自行提供的 Driver，其传输政策由宿主负责。见[安全与边界](security-and-boundaries.md)。

`InferenceBackendDef.io_window_bytes` 设置请求编码和解析工作的窗口，默认 16,384 字节，接受任意正整数。单字节窗口也支持跨窗口的 UTF-8 字符和 JSON 转义；该窗口不限制请求、响应或 SSE 事件的总长度。输出通道仍通过 `StreamWindow` 独立配置，HTTP 库另行持有其传输缓冲区。记录校验完成后，已选文本按此窗口分块输出，并保留完整 UTF-8 字符；窗口小于一个字符时，该块最多包含四字节。输出通道计入编码后的块及其来源元数据。

`response_limits` 将结果物化策略独立配置：

- `max_materialized_bytes`：单个 unary 响应或原子 SSE 记录内同时保留的已选文本和数字 token 字节。
- `max_materialized_nodes`：保留的已选值节点数，包含空值。
- `max_json_frames`：同时打开的 JSON 容器数，包含被跳过的数据。

所有上限均为可选；未设置的维度不施加配额。字节和节点计数是逻辑准入单位，不代表分配器或进程 RSS 上限。已知控制标签和字段名有固定存储开销，不计入已选 token 字节。最终 unary 输出及每条原子 SSE 增量仍需驻留存储，应用可以显式约束这些结果的物化，而不限制任务累计数据量。未使用的 Provider 字段会增量校验，不会组成完整 JSON 包。例如，OpenAI Responses 完成快照中重复的输出文本不会被保留。

SSE 记录必须完整结束且 JSON 校验通过，才会交付该记录中选中的 delta。后到的错误或非法后缀不会使同一记录的前缀提前发布。解析器只移除流开头的一次 UTF-8 BOM，并同样校验跳过的数据。各适配器保留其声明的 delta 语义，不会凭文本重复自行猜测累计快照。HTTP 错误诊断固定读取最多 8 KiB 前缀，展示最多 512 个脱敏字符，与成功响应的准入相互独立。达到前缀上限后停止读取，无需等待服务端结束响应体；若服务端在此之前停滞，仍需请求取消或客户端超时处理。字节上限不会隐式施加响应持续时间策略。

嵌入式宿主通过 `StandardConfig::with_object_store` 显式安装对象能力。`ObjectStore` 分别接收读、写和删除适配器；`xolotl-storage-fs::FileObjectStore::open(root)` 提供文件实现。Fetch 和文件读取的大型 unary 输出、Blob 写入及 Tensor 写入需要对象写入端口；Blob 读取和删除需要对应端口。流式 Fetch 和文件读取无需安装对象存储。

`FileObjectStore::with_options(root, FileObjectOptions)` 配置非零额度；`open(root)` 使用以下默认值：

| 选项 | 默认值 | 计费资源 |
| --- | --- | --- |
| `chunk_bytes` | 64 KiB | 单次 chunk 请求接受或返回的字节 |
| `max_uploads` | 64 | 创建中、存活、丢失回执及延后清理的上传责任 |
| `max_io_tasks` | 8 | 并发前台文件系统作业及其驻留 chunk 缓冲区 |
| `max_metadata_bytes` | 1 MiB | 单对象编码后的 metadata，包含来源 |

Clones 共享拥有者的上传与 I/O 额度；独立打开的实例各有独立预算，即使使用相同根目录。上传容量在创建 staging 前以非等待方式预留；额度耗尽时在该文件系统效果发生前拒绝上传。清理另有一个工作线程，不占前台 I/O permit；排队及运行中的清理仍占上传槽位。这些额度不限制对象总字节、磁盘垃圾或进程 RSS。清理、回执重取及平台持久性见 [API 参考](api-reference.md)和拥有该规则的[对象存储合同](architecture.md)。

控制台认证、WebSocket 和传输安全字段是部署设置。能力检查、二次确认门槛、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。
