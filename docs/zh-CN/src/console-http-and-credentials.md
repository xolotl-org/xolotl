# Console HTTP 与凭据

本页说明相对 HTTP 路由、认证会话和凭据管理。它们共用 [Console 服务](console-protocol.md)；资源调用和保留提交见 [运行时调用与提交](console-runtime.md)。

## HTTP 路由

`http::serve()` 将所有入口挂载到默认前缀 `/api/console/v1`。`http::router(adapter)` 返回相对于挂载点的路由；下表路径也以该挂载点为准。

`HttpApi` 从同一目录的 20 个操作端点中装配路由组或单个 `HttpEndpoint`，清单另计。`HttpApi::new()` 从空端点集开始，`HttpApi::all()` 选择全部。`.router(adapter)` 安装所选路由，并在 `GET /` 返回其 method/path、编码和认证要求；例如 `.nest("/admin", ...)` 时可在 `/admin` 读取。`.routes(adapter)` 安装同一组所选路由，但不占用宿主根路径，也不自动发布清单；宿主可以把 `HttpApi::manifest(&adapter)` 发布在自选路径，并设置 `Cache-Control: no-store`。

清单路径相对于这些路由的挂载点，不是绝对 URL；若宿主另加前缀，须自行解释。清单描述所选路由集，不描述宿主其他路由或其他挂载点。

宿主以 `HttpApi::with_group(HttpGroup::...)` 选择路由组、`HttpApi::with_endpoint(HttpEndpoint::...)` 选择单个端点；可用 `without_group` 与 `without_endpoint` 收窄已组装的集合，再挂载所选路由。每组保留表中的命名空间。

使用 `Arc<ConsoleState>` 和 `HttpConfig` 创建 `HttpState`。同一 service 的适配器共享凭据、注册表、调用/订阅容量和执行预算；每个 `HttpState` 独立拥有 Origin/proxy、自动化客户端省略 Origin 的策略及 WS 连接、帧和发送限制。复用同一 `Arc<HttpState>` 挂载到多个前缀或监听器时共享连接计数，不同实例分别计数。Tracing、CORS 及其他应用中间件由宿主装配；Console 自身验证浏览器 Origin 和 bearer。

TCP 宿主可用 `into_make_service_with_connect_info::<SocketAddr>()` 提供真实连接地址；需要连接绑定的自动化客户端证明时改用 `HttpTcpConnection`。Unix domain socket 等非 TCP 宿主应在可信连接边界验证 peer，调用 `HttpPeer::verified_source(name)`，再把所得值作为 Axum `Extension` 注入该连接的请求。普通 HTTP 客户端不能直接提供 Axum extension；宿主不得从客户端可控请求头构造它。有界来源名只用于审计及限流，不代表账户身份或授权。

默认 POST 请求和 WebSocket upgrade 仍需 `Origin`；下述三个只读 GET 可以省略。对 POST 不发送该头的非浏览器自动化客户端，宿主须显式将 `HttpConfig.originless_clients` 设为 `OriginlessClientPolicy::AllowVerifiedAutomation`。TCP 宿主使用 `into_make_service_with_connect_info::<HttpTcpConnection>()`，使 Axum 为每条已接受的连接发放唯一的 `ConnectInfo<HttpTcpConnection>`；独立验证连接后，将 `VerifiedAutomationClient::for_tcp_connection(&tcp_connection)` 作为 Axum `Extension` 注入。非 TCP 宿主使用 `VerifiedAutomationClient::for_host_peer(&verified_http_peer)`。

Console 会核对证明与真实连接来源。套接字地址被复用也不会复用 TCP 连接证明；非 TCP 请求须注入同一 `HttpPeer` 实例或其 clone，重新构造相同来源名也不会复用连接证明。不得仅凭 bearer、客户端请求头、转发地址、来源 IP 或未验证的共享监听器构造此证明。该策略只允许省略 HTTP `Origin`，不代表账户认证或动作授权。

认证、凭据、调用和 WebSocket 端点缺少来源，或同时收到 `HttpPeer`、`ConnectInfo<SocketAddr>`、`ConnectInfo<HttpTcpConnection>` 中的多种时拒绝请求，不将缺失来源默认为 `unknown`。公开的 HTTP 清单和健康端点不使用连接来源。

交互式 step-up 还需要认证组的 `/auth/continue` 与 `/auth/cancel`，也可通过同一 service 的其他适配器继续；选择 session 组不会隐式挂载这些端点。

JSON 请求体最多 64 KiB；只有 `/auth/external` 为容纳 64 KiB 断言的 base64url 与 JSON 编码，允许 96 KiB；单个因子输入、setup、verifier 及交互载荷最多 16 KiB。

清单的 `transport` 描述该适配器的传输策略，`originless_clients` 描述配置的省略 Origin 准入策略，不证明某个请求已获得宿主验证；仅选择 WS endpoint 时包含 `websocket` 限制，其中 `idle_timeout_ms` 和 `send_timeout_ms` 均为毫秒整数。清单还包含该适配器生效的整数毫秒 `request_body_timeout_ms`。`HttpApi::manifest(&adapter)` 可以在挂载前读取相同描述。service 的发现及 `health.summary` 不推断监听器，也不返回 WS 配置。

`HttpConfig.request_body_timeout` 默认 30 秒（范围 1 秒至 5 分钟），daemon 配置键为 `console.request_body_timeout_ms`。它约束 JSON 认证和 protobuf `/calls` 的请求体收取，超时返回 HTTP 408 并释放已取得的认证或动作额度。读取正文和占用共享额度之前先验证连接来源、Origin 与必需的 bearer 头格式；公钥登录即使来自已验证自动化客户端也要求真实 Origin。bearer 是否有效仍由解码后的服务层判断。请求体收完后的服务执行不受此计时器限制。

请求体收取将同一共享准入凭据移交服务分派，持续持有到验证或凭据变更完成。返回结果（包括 continuation）、输入错误、超时、handler 检查拒绝和取消均释放额度。账户权限及持久挑战额度分别计量。原生宿主可通过 `ConsoleService::admit_authentication` 取得并消费 `ConsoleAuthenticationAdmission`；普通服务方法自动取得同一类凭据，不跨客户端等待时间保留并发额度。

```rust,ignore
use xolotl_console::http::{self, HttpConfig, HttpState};
let adapter = HttpState::new(console_state, HttpConfig::default());
let app = axum::Router::new()
    .nest("/admin", http::router(adapter.clone()));
// 另一挂载点复用相同的适配器准入：
let app = axum::Router::new()
    .nest("/automation", http::HttpApi::new()
        .with_endpoint(http::HttpEndpoint::Calls)
        .routes(adapter.clone()));
// 宿主已占有 GET / 时，可合并所选路由而不安装根清单：
let api = http::HttpApi::new().with_endpoint(http::HttpEndpoint::Health);
let manifest = api.manifest(&adapter);
let app = axum::Router::new()
    .route("/", axum::routing::get(|| async { "host root" }))
    .merge(api.routes(adapter));
// 宿主可在自选发现路径发布 `manifest`。
```

| 相对路径 | 方法 | 用途 |
| --- | --- | --- |
| `/health` | `GET` | 健康检查（纯文本） |
| `/auth/password/login` | `POST` | 验证密码及随附的 `second_factor`，或返回因素选择步骤 |
| `/auth/external` | `POST` | 验证不透明断言，并由宿主账户权威定位账户 |
| `/auth/keys/challenges` | `POST` | 创建公钥登录挑战 |
| `/auth/keys/login` | `POST` | 验证公钥签名及所需第二因子 |
| `/auth/passkeys/challenges` | `POST` | 开始 Passkey 登录 |
| `/auth/passkeys/login` | `POST` | 完成带用户验证的 Passkey 登录 |
| `/auth/factor-providers` | `GET` | 发现已安装的因子提供者及注册／认证 schema |
| `/auth/continue` | `POST` | 用不透明 continuation 继续登录或 step-up |
| `/auth/cancel` | `POST` | 取消该次认证，成功返回 JSON `null` |
| `/session/step-up` | `POST` | 验证新的因子证明，或省略 `proof` 选择因素；要求现有 bearer |
| `/session/refresh` | `POST` | 轮换 bearer secret，保留会话认证时间 |
| `/credentials` | `GET` | 读取当前账户的主凭据元数据 |
| `/credentials` | `POST` | 管理主凭据；指定其他账户需要管理权限 |
| `/credentials/passkeys/registration` | `POST` | 近期认证后开始注册 Passkey |
| `/credentials/passkeys/registration/confirm` | `POST` | 确认并保存 Passkey 凭据 |
| `/credentials/factors` | `GET` | 读取本人的绑定方法及剩余恢复码数量 |
| `/credentials/factors` | `POST` | 提交带 operation 标签的 MFA 管理操作 |
| `/calls` | `POST` | 执行一次经过认证的 protobuf v1 动作 |
| `/ws` | `GET` | 升级为 protobuf v1 调用及实时订阅 |

`POST /calls` 接收一个 protobuf `ConsoleFrame.call`，要求 `Authorization: Bearer <token>`、`Content-Type: application/protobuf` 及传输策略要求的 `Host`、`Origin`；无需 Hello 或 Auth 帧。返回 `ConsoleFrame.reply` 或 `ConsoleFrame.error`，并设置 `Cache-Control: no-store`；解码帧之后的错误保留请求 ID，读取正文前的准入错误没有请求 ID。请求体超过 4 MiB 返回 413，内容类型不支持返回 415；响应编码也限制为 4 MiB，并受 Value 转换预算约束。此端点只执行动作；实时订阅使用 WebSocket 或 `ConsoleService::subscribe`。Protobuf 无损保留字节、大整数标识和特殊 Value。

```sh
curl https://console.example/api/console/v1/calls \
  -H 'Origin: https://console.example' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/protobuf' \
  --data-binary @request.pb --output reply.pb
```

退出和管理员撤销会话使用描述符动作 `access.session.current.logout`、`access.session.revoke` 和 `access.session.revoke_user`，通过 Rust `call`、`/calls` 或 WebSocket 调用，复用同一授权及审计流程。

### 来源、Origin 与代理

浏览器 POST 认证及调用请求需要 `Origin` 和 `Host` 请求头。同源浏览器 GET 往往不发送 `Origin`，JavaScript 也不能手工设置该请求头，因此 `GET /auth/factor-providers`、`GET /credentials` 和 `GET /credentials/factors` 在验证连接来源与唯一合法的 `Host` 后允许省略 `Origin`；后两个私有读取仍需 bearer。GET 若带有 `Origin`，仍须严格校验。

只有配置了显式策略、且宿主验证证明与真实连接来源匹配的自动化客户端，可在 HTTP POST 认证、凭据及调用路由省略 `Origin`。`Host` 始终必需；只要提供了 `Origin`，就必须完整通过校验。公钥 challenge、登录和所有 WebSocket upgrade 始终需要真实的 `Origin`，即使是已验证自动化客户端。

origin 的 host、port 以及可信 forwarded scheme 必须匹配控制台监听器对外可见的 host。两个请求头各自只接受一个明确的值；即使使用可信代理，重复头和逗号组合值也会被拒绝。HTTP(S) 的默认端口与省略端口等价，等价的 IPv6 地址写法也可匹配。

公钥登录还要求 JSON 里的 `origin` 字段与请求 `Origin` 头完全一致；该值会绑定进签名 transcript。Passkey 路由使用配置中的 WebAuthn relying-party id 和 origin，不规定任何前端布局或 UI 框架。

两个 continuation 端点在清单中声明 `authentication: "continuation"`。登录只需 continuation；step-up 额外要求发起 SID 的当前有效 bearer。两者都执行相同的 Origin 检查。Authorization 缺失时传入 `None`；已提供但格式错误、为空、重复或合并的 bearer 头会被拒绝，不能当作缺失处理。step-up 的会话绑定由服务层核验。

只有 socket peer 可信且启用 `honor_x_forwarded_for` 时，来源转发头才参与审计和限额。Console 将重复的 `X-Forwarded-For` 头按顺序合成链，从右向左越过可信代理 IP，取第一个不可信 IP；全部可信则取最左 IP。扫描后缀中出现空项、畸形值或非 IP 项时回退 socket peer，不再尝试 `X-Real-IP`。

仅当 XFF 完全缺失时才接受单个 `X-Real-IP` 头中的一个 IP，并规范化其文本；重复或含逗号的值不被采信。不可信 peer 或未启用转发时直接使用 socket peer。使用 `X-Real-IP` 后备的可信代理必须覆盖或移除客户端传入值；单个合法 IP 不能证明其来源。

宿主验证的非 TCP peer 没有代理 IP，直接使用其来源 key；`X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Host` 和 `X-Forwarded-Proto` 均不能覆盖该来源或外部 origin 检查。`Host` 始终必需；前述显式策略只能豁免合格 HTTP 路由完全缺失的 `Origin`，不能让转发头变得可信。

可信且启用的 `X-Forwarded-Host` 和 `X-Forwarded-Proto` 各自只接受一个不含逗号的头值。代理必须覆盖客户端传入值，重复或组合值会导致 Origin 准入被拒绝。这些规则同时适用于 HTTP 调用/认证和 WebSocket upgrade；部署配置见[控制台传输配置](configuration.md)。

## 认证和会话

密码 hash 生成及验证在 Tokio 阻塞线程池执行，共用 `argon2_concurrency` 限额。满载时返回 `RATE_LIMITED`（HTTP 429），不编造重试期限或排队等待；取消请求后仍占用额度，直到阻塞任务退出。

密码登录请求：

```json
{"username":"root","password":"...","second_factor":null}
```

外部主认证由宿主在 `ConsoleConfig.external_authentication` 安装 `ExternalPrimaryAuthentication`。`ConsoleService::exchange_external` 接收不透明断言字节；HTTP `/auth/external` 接收 `{"assertion":"<无填充-base64url-断言>"}`，沿用认证路由的 HTTP Origin 策略、`Host`、已验证 peer、请求体上限、审计、账户与 MFA 准入。

宿主的外部认证准备许可从验证持续持有到账户查询及会话或有界 continuation 准入。慢账户服务不能在验证完成后形成未计量队列；完成和取消释放许可，已返回的 continuation 则由挑战 ledger 计量。

宿主 verifier 须先验证签名、issuer、audience、有效期和重放策略，再返回稳定的 provider／issuer／subject、断言验证时间、可证的用户认证时间（可空）、绝对有效期及保证描述。

另由 `ConsoleConfig.account_authority` 安装的账户权威将已验证事实解析为稳定 `AccountKey`，并读取当前状态、本地 `identity://...` 路径、grants 和撤销代际；Console 拒绝停用、重建或凭据代际变化的账户。

本 crate 不内置 OIDC verifier。转发头、`HttpPeer` 名称、应用 Gateway principal 和客户端提供的用户名都不是身份证明。

发证时 Console 将当前账户 grants 固定为会话权限上限；超过 128 条能力、能力文本合计 8 KiB 或单条 2 KiB 时拒绝发证。每次请求及订阅交付与最新账户 grants 取可证明的交集，保留较窄路径和谓词；无法表达的条件交集保守拒绝。verifier 不提供资源授权。

安装宿主账户权威后，本地密码、公钥及 Passkey 主登录不可用；Console 仍管理 bearer 会话和按账户键保存的第二因素。外部主证明均按 Console MFA level 1 处理，即使 verifier 报告 `multi_factor` 保证，已绑定的 Console 因子仍进入常规 continuation。当前没有把特定外部保证映射为 Console level 2 的策略。

外部 `valid_until` 限制 MFA continuation、会话绝对期限和空闲期限。因素完成、step-up 与凭据变更后再发证不能延长它；refresh 保留绝对期限。

每次 bearer 调用与订阅交付重新核对期限、账户键、当前撤销代际、身份路径和 Console 凭据代际。账户权威的撤销在这些读取中生效；若撤销只发生在断言签发方，还需宿主接入，否则等待断言过期。已接受任务保留原截止时间，独立于 bearer 生命周期检查当前账户权威。

HTTP 和 WebSocket 后续调用使用兑换后的普通 Console bearer；这个 bearer 不能证明另一连接仍持有 mTLS 私钥。

公钥挑战请求：

```json
{"username":"root","origin":"https://console.example"}
```

公钥登录请求：

```json
{"username":"root","challenge_id":"...","signature":"...","origin":"https://console.example","key":"ml-dsa-65:<base64url-public-key>","second_factor":null}
```

公钥、Passkey 和 MFA 认证 continuation 共享 `state://vault/console/challenges` 下的有界 CAS 记录。`console.auth.challenges` 默认全局 256、每账户 8、每个已验证来源 32 个待完成仪式，总编码上限 1 MiB、单个载荷上限 64 KiB；来源只存 hash。并发创建不能突破上限。

公钥和 Passkey 的消费 CAS 在删除挑战前匹配用途及所有者：公钥登录绑定 username 与 origin，Passkey 注册绑定 username 与发起 SID，Passkey 登录绑定 username。错误绑定不消耗挑战；绑定匹配后，在验证证明前单次消费，即使证明无效也不能复用。来源地址只用于配额和审计，不参与此绑定，切换网络不使挑战失效。

创建时清理过期项，响应丢失占用的容量最多保留到过期。共享 State 的宿主共享该记录，必须使用相同限额。容量耗尽返回 `RateLimited`，不编造重试时间。

Passkey 注册 begin 请求：

```json
{"label":"Operator passkey","display_name":"Root Operator"}
```

Passkey 注册 begin 和 finish 要求：

```text
Authorization: Bearer <token>
```

Passkey 登录 begin 请求：

```json
{"username":"root"}
```

Passkey finish 请求携带浏览器从 `navigator.credentials.create` 或 `navigator.credentials.get` 返回的 credential response。

Step-up 请求体：

```json
{"proof":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}
```

空对象或 `"proof": null` 表示开始因素选择，不直接验证证明，也不刷新会话的认证时间。

`/session/step-up` 通过以下请求头传入现有会话：

```text
Authorization: Bearer <token>
```

密码登录、公钥登录和 step-up 返回 `AuthenticationResponse`：

| `result` | 字段与含义 |
| --- | --- |
| `authenticated` | `session: LoginResponse`，全部必要验证已提交 |
| `continue` | `continuation`、`expires_at`、`step`，认证尚未完成 |

两种结果均为 HTTP 200。Rust 客户端可匹配 enum，或调用 `into_session()`：成功分支得到会话，`Err` 分支保留 `AuthenticationContinuation`。登录续接绑定本次已验证的主证明；step-up 绑定原会话的完整证据和独立的 SID 用途。continuation 只允许继续或取消本次认证，不能授权普通调用、凭据管理或 WebSocket 认证。选择第二因素无需重新提交密码或公钥签名；已经提交但无效的 proof 仍返回认证失败。

Passkey 登录与 refresh 直接返回 `LoginResponse`；凭据管理在原结果类型中包含替代会话。`LoginResponse` 字段如下：

| 字段 | 含义 |
| --- | --- |
| `sid` | 会话 ID |
| `token` | `sid.secret` 形式的 bearer token |
| `expires_at` | 绝对过期时间，Unix 毫秒 |
| `idle_expires_at` | 空闲过期时间，Unix 毫秒 |
| `authentication` | 完整的 `AuthenticationEvidence`，形态见下文 |

`authentication` 包含必填的 `primary` 对象及必填可空的 `secondary`。每份非空证明都有实际验证完成时的 `verified_at`，单位为 Unix 毫秒：

| 证明 | `method` | 凭据引用 |
| --- | --- | --- |
| 主证明 | `password` | 账户唯一密码槽位，不保存凭据 ID 或密码 hash |
| 主证明 | `public_key` | `credential_key`：实际通过验证的规范 ML-DSA-65 描述符 |
| 主证明 | `passkey_uv` | `credential_id`：实际验证的 base64url WebAuthn 凭据 ID，UV 已通过 |
| 主证明 | `external` | 已验证的 `provider`、`issuer`、稳定 `subject`、可空用户 `authenticated_at`、断言 `valid_until` 及描述性的 `assurance`，不含断言秘密 |
| 第二证明 | `factor` | `factor_id`，以及从该存储实例取得的 `provider_id` |
| 第二证明 | `recovery_code` | 不保存恢复码、摘要或数组位置 |

服务在验证成功时固定时间，后续异步存储或发证不能刷新它。账户键、撤销代际和 Console 凭据 epoch 由会话包络保存；凭据引用描述历史验证，后续经授权删除凭据不会改写历史。step-up 保留原主证明，只替换第二证明，SID 归属与两份证明分开。凭据管理和 refresh 完整保留证据。持久会话必须有认证证据；缺失时直接拒绝。

Rust 客户端可调用 `authentication.mfa_level()` 和返回 `Option<i64>` 的 `authenticated_at()`；greeting、会话列表、权限及审计投影按用途提供派生摘要。密码/公钥单独验证为 level 1，具有独立第二证明或 `passkey_uv` 时达到当前 level 2。数字本身不保证抗钓鱼或排除恢复认证，这类要求必须检查证明种类。近期门槛只取可证的用户认证时间或本地第二证明时间；外部断言 `verified_at`、token 签发时间和本次兑换时间均不能打开近期认证窗口。用户认证时间缺失时，审计与会话列表摘要写 `null`，直到本地因素提供实际验证时间。

continuation 的 `expires_at` 是固定的 Unix 毫秒绝对期限。`step.kind` 决定接受哪种 `AuthenticationInput`：

| `step.kind` | 公开字段 | 接受的 `input.kind` |
| --- | --- | --- |
| `choose_factor` | `options` 包含账户 `factors` 和 `recovery_code_available` | `proof` 携带 `proof: MfaProof`，或用 `select_factor` 和 `factor_id` 开始交互 provider |
| `challenge` | `factor_id`、`provider_id`、provider 的 `challenge` | `response` 携带 provider 专属 `response` |
| `pending` | `factor_id`、`provider_id`、provider 的 `status`、`retry_after_ms` | 等待指定时间后提交 `poll` |

`POST /auth/continue` 接收 `ContinueAuthenticationRequest`。因素选择后可直接提交 TOTP：

```json
{"continuation":"...","input":{"kind":"proof","proof":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}}
```

同一 `proof` 字段也接受 `{"kind":"recovery_code","code":"..."}`。交互认证则先选择因素：

```json
{"continuation":"...","input":{"kind":"select_factor","factor_id":"<enrolled-factor-id>"}}
```

后续 challenge 的输入为 `{"kind":"response","response":...}`，内容遵循该 provider 的 schema；pending 输入为 `{"kind":"poll"}`。每次消费后返回会话或新的 continuation，客户端应替换保存的 token。通过当前策略与账户准入后，过早轮询返回原 token 和剩余等待时间，不调用 provider。账户、用途、选定因素和原 step-up SID 由宿主固定，输入不能替换这些绑定；切换网络不改变归属。

`POST /auth/cancel` 接收 `CancelAuthenticationRequest`：

```json
{"continuation":"..."}
```

成功返回 HTTP 200、JSON `null` 和 `Cache-Control: no-store`。step-up 的 continue 和 cancel 均要求原 SID 的当前有效 bearer；登录 continuation 不需要普通会话。已选定交互因素后，如需切换因素，应取消并重新开始认证。

`POST /session/refresh` 从 `Authorization` 取得现有 bearer。轮换前检查会话和账号启用状态，只更换 secret，保留 SID、完整认证证据及绝对过期时间，延长空闲活动窗口。共享服务记录结果及已验证来源。轮换和审计不是跨记录事务；响应丢失，或轮换后审计写入失败时，客户端可能需要重新登录。

会话与 bearer verifier 是 `ConsoleSessionStore` 拥有的同一私有聚合，独立于 State 及其历史。存储按共享的账户与存储域容量原子接纳会话；过期行在删除前仍占容量，宿主须安排有界维护。同一 bearer 的并发刷新至多一个获胜，陈旧活动不能恢复旧 verifier。`state://kernel/console/sessions` 是管理授权目标，不是 State 中的记录副本；会话列表只投影已授权摘要，不含 verifier、凭据 epoch 或授权上限。会话提交不与账户或审计更新构成共同事务。存储、淘汰、条件更新与不确定提交规则以[会话存储 rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-console/src/session_store.rs)为准。

只读 SID 验证在异步账户与凭据检查后重读私有会话，要求不可变权威未变且硬／空闲期限仍存活。并发活动或 bearer 轮换本身不撤销 SID；只读验证不续期、不写会话。主动认证与刷新以最初有效准入时间为续期锚点，而非等待完成时间，并在提交前后检查存活；签发也在提交后检查实际会话。迟到操作不能交付已过期会话，也不能靠等待无限续期。这些终点观察不锁住后续撤销，也不把账户、凭据与会话检查变成原子事务。

认证响应使用 `Cache-Control: no-store`。错误统一返回 JSON `ConsoleFailure`，包括 JSON 解析和请求体超限失败；code 使用 snake_case，例如 `not_authenticated`、`rate_limited`。未知的恢复字段省略，输入错误诊断不回显凭据值。

HTTP 认证错误映射：

| 情况 | 状态 |
| --- | --- |
| 缺少 bearer、无效会话、无效挑战或无效凭据 | `401 Unauthorized` |
| 操作要求更强认证 | `403 Forbidden`，`step_up_required`；普通动作门槛不附带账户因素 |
| 账号不可用或权限不足 | `403 Forbidden` |
| 宿主禁止所选因素 provider 的用途 | `403 Forbidden`，`forbidden`，不累计错误凭据次数 |
| 因素 provider 未安装，或允许的用途未声明所选操作 | `422 Unprocessable Entity`，`admission_rejected`，不累计错误凭据次数 |
| 超过速率限制 | `429 Too Many Requests` |
| 用户名无效 | `400 Bad Request` |
| 凭据并发修改 | `409 Conflict`，不推测当前 revision |
| 删除最后一个主凭据 | `422 Unprocessable Entity`，`admission_rejected` |
| JSON 语法错误／数据结构错误／内容类型不支持／请求体超限 | `400`／`422`／`415`／`413`，code 为 `bad_request` |
| 内部认证状态或加密失败 | `500 Internal Server Error`，返回脱敏消息 |

## 主凭据管理

本节适用于由 Console 管理的本地账户。安装宿主 `AccountAuthority` 后，主账户生命周期由宿主负责，Console 拒绝本地主凭据操作；按账户键保存的第二因素仍由 Console 管理。

`ConsoleService::credentials` 与 `POST /credentials` 接收 `CredentialRequest`。省略 `username` 表示操作当前认证账户。`GET /credentials` 读取该账户的凭据元数据，不要求再次提供证明。JSON 中的 operation 为嵌套对象：

```json
{"operation":{"action":"set_password","password":"..."}}
```

| `operation.action` | 其他 operation 字段 | 效果 |
| --- | --- | --- |
| `status` | 无 | 密码启用状态/变更时间、公钥、Passkey 标签/ID/使用时间及限额 |
| `set_password` | `password` | 按内置强度策略设置或替换密码 |
| `disable_password` | 无 | 停用密码，必须保留其他主凭据 |
| `add_public_key` | `key` | 添加原始公钥长 1,952 字节、格式为 `ml-dsa-65:<base64url>` 的规范描述符 |
| `remove_public_key` | `key` | 撤销指定公钥描述符 |
| `rename_passkey` | `credential_id`、`label` | 修改 1–128 字节标签，不使会话失效 |
| `revoke_passkey` | `credential_id` | 删除 Passkey，使旧会话和待使用登录挑战失效 |
| `reset_second_factors` | 无 | 管理员恢复其他账户：清空第二因子、待确认绑定和恢复码 |

查询返回 `status: "current"`；修改返回 `status: "updated"`、`sessions_invalidated` 和可选替换 `session`。改变凭据权限的操作与 MFA 使用同一 vault epoch；修改自己的凭据时返回新会话，客户端应立即切换。仅修改主凭据时保留原认证时间，不能反复修改来延长近期认证窗口；只改标签不轮换 epoch。每账户最多 32 个公钥和 32 个 Passkey。不能删除最后一个主凭据，TOTP 和恢复码属于第二因子，不能单独代替主登录。密码生成 hash 与验证共用有并发上限的阻塞任务池。

初始化或重置其他账户时指定 `username`，要求近期 level 2 认证、`perform://effect/kernel/console/users`、目标账户写权限，以及覆盖目标有效授权和授权上限的能力。只有 root 可以管理 root 凭据。修改其他账户不会签发该账户的会话。先以 `access.user.write_cas` 创建账户元数据，再通过凭据服务配置密码或公钥。没有主凭据的账户不能登录；配置凭据失败不会让账户变为可用。

账户元数据不包含凭据 verifier 或认证证据。服务创建账户时生成不可变 `account_id`，客户端创建时省略它，更新时也可省略，不能替换为其他 ID。凭据绑定账户 ID，同名账户重建不会继承旧 vault 凭据。本地会话还将账户元数据版本作为撤销代际，修改账户或禁用后再启用都需要重新登录；每次访问重新读取当前 grants。

Passkey 注册请求包含 `label` 和可选的认证器 `display_name`；挑战绑定当前凭据 epoch 及发起 SID，确认返回 `credential_id` 和替换 `session`。注册、密码/公钥修改及撤销通过聚合记录原子提交，旧登录计数或第二因子更新不能恢复已撤销凭据。公钥及 Passkey 登录挑战也绑定凭据 epoch，删除后重新添加同一凭据不能复用旧挑战。WebAuthn 验证宿主配置的 RP/Origin，仅用户验证成功的 assertion 可签发 level 2。凭据 CAS 竞争返回冲突，已失效 token 需要重新登录。凭据提交、后续会话签发和审计交付是独立步骤；响应丢失后应以当前凭据重新认证并查询状态。

## 第二因子与凭据生命周期

未绑定独立因子时，密码和公钥登录签发 level 1 会话。绑定后，主凭据正确但未附带 `second_factor` 时返回 `result: "continue"` 和 `step.kind: "choose_factor"`。密码错误时不披露绑定情况。TOTP 或恢复码可随初始请求提交，保留一次请求完成认证的路径。通过用户验证的 Passkey assertion 经 WebAuthn 签发 level 2。重复校验密码不能提升至 level 2；已有 bearer 可以向 `/session/step-up` 提交新的因子证明。

```json
{"username":"root","password":"...","second_factor":{"kind":"factor","factor_id":"<enrolled-factor-id>","response":{"code":"123456"}}}
```

`GET /auth/factor-providers` 返回已安装提供者的 `{descriptor, usage}` 记录，不包含账户绑定信息。`usage` 分别给出宿主的 `allow_enrollment` 和 `allow_authentication` 决定。每份 descriptor 包含 `provider_id`、`label`、可选的 `enrollment`（可选 `begin_schema`，必需的 `setup_schema`，可选 `pending_schema`）和 `authentication`（可选 `proof_schema`、可选 `interaction`，后者含 `challenge_schema`）。每轮挑战步骤各自提供 `response_schema`，相邻轮次可要求不同输入。必须声明至少一种认证路径；缺失能力不可用，注册响应不会隐式使用认证 proof schema。宿主装配时检查声明中 schema 的顶层为对象或布尔值及其字节、深度上限，之后为该宿主固定。Provider 返回挑战时，宿主检查该轮响应 schema。发现和注册准入使用同一份声明。Console 不完整校验 JSON Schema 语法，也不按 schema 对请求值逐字段求值；provider 应发布一致的 schema，并自行校验收到的输入、证明的结构与语义。

`GET /credentials/factors` 要求 bearer，返回 `result: "status"`、`providers`、`factors`、`max_factors` 和 `recovery_codes_remaining`。每个因素摘要包含不透明 `factor_id`、`provider_id`、用户 label、`created_at`、可选 `last_used_at` 及 `availability`。时间单位是 Unix 毫秒；`last_used_at` 记录已提交的登录或 step-up，不包括注册激活。可用状态为 `provider_not_installed`、`authentication_disabled` 或 `available`；最后一种表示当前宿主允许使用已安装 provider 声明的认证路径，客户端仍须检查 descriptor 来选择直接 proof 或交互；可用状态不预测外部依赖健康状态。JSON、HTTP protobuf 和 WebSocket protobuf 均保留这三种状态。恢复码使用独立的账户级证明类型，由宿主在第一个因素激活时生成。

provider 分发同时要求实现已安装、声明支持该操作以及宿主允许使用。注册开始及每次推进均检查注册策略；直接证明、登录、step-up 和交互的每轮（包括过早 Poll）都检查认证策略。策略拒绝返回 HTTP 403、JSON code `forbidden`；未安装实现或允许用途下未声明的操作返回 HTTP 422、`admission_rejected`。已安装时先检查宿主允许决定，再检查操作声明。两者均不计入错误凭据次数。服务在领取每轮 claim 前检查这些条件，另一实例的拒绝不会消费原轮次；原期限和 SID 绑定继续有效。

禁止新使用不改写已存因素、凭据 epoch 或会话历史证据，也不取消账户已有的第二证明要求。列出、取消、改名、删除和恢复码使用保留原授权规则；Passkey 主认证与 provider 使用策略分开。配置方式见[provider 安装与使用](configuration.md#mfa-provider-安装)。

本节路径均相对于所选路由的挂载点；daemon 的 `http::serve()` 默认使用 `/api/console/v1`。`POST /credentials/factors` 使用与 `ConsoleService::mfa` 相同的带标签 `MfaRequest`：

| operation | 其他字段 | 结果 |
| --- | --- | --- |
| `status` | 无 | 与 GET 相同的状态 |
| `current` | 无 | 返回当前 SID 的待注册 `enrollment` 及公开步骤，或 `no_enrollment`；要求近期凭据管理认证 |
| `begin` | `provider_id`、`label`、可选 `replace_factor_id`；声明 `begin_schema` 时还需 `input` | `enrollment`，含 `challenge_id`、新 `factor_id`、`provider_id`、`label`、`expires_at` 和 `step` |
| `continue` | `challenge_id`、`input`（挑战时为 `response`，等待时为 `poll`） | 下一轮 `enrollment`，或含新 `session`、可选 `recovery_codes` 的 `updated` |
| `cancel` | `challenge_id` | `canceled` |
| `rename` | `factor_id`、`label` | `renamed`，返回当前因素摘要；已有会话仍有效 |
| `remove` | `factor_id` | `updated`；保留原会话认证证据，移除最后因子会清空恢复码 |
| `regenerate_recovery_codes` | 无 | `updated`，含新会话及替换后的恢复码 |

绑定使用近期认证的 bearer。`begin_schema: null` 表示不接受 `input`；声明 JSON Schema 时必须提交 `input` 字段。显式 `input: null` 属于已提交输入，如果 provider schema 允许，它可以是有效值。宿主在调用 provider 前拒绝缺失、多余、编码后超过 16 KiB 或嵌套超过 32 层的 begin 输入。Provider 可用 `MfaProviderError::InvalidInput` 拒绝值的语义，对客户端返回错误请求；该结果承诺外部注册未被接受，宿主因此恢复此前准备中的轮次。宿主只在这次调用中借用输入；待注册项保存当前公开步骤及 provider 的私有轮次状态，不保存原始输入。仅在最后验证完成时保存 verifier。TOTP 不声明 begin 输入。其 setup 返回 Base32 `secret`、正确编码的 `otpauth_uri`、`algorithm`、`digits` 和 `period_seconds`。客户端可自行生成二维码或提供手动录入，宿主不绑定前端框架、二维码库或认证器应用。TOTP 挑战的推进请求示例：

```json
{"operation":"continue","challenge_id":"...","input":{"kind":"response","response":{"code":"123456"}}}
```

注册是独立于登录 continuation 的账户写入流程。`begin_enrollment` 返回挑战或等待状态；每次 `continue_enrollment` 可返回下一轮挑战、等待状态或最终验证成功。`enrollment.step` 的 `kind: "challenge"` 携带 provider 的 `setup` 和该轮 `response_schema`，`kind: "pending"` 携带 `status` 和 `retry_after_ms`。轮询请求为 `{"operation":"continue","challenge_id":"...","input":{"kind":"poll"}}`。非终态轮次成功提交后轮换 `challenge_id`；默认最多调用 provider 16 次，包含 begin 和最终验证。在 `retry_after_ms` 前轮询只返回剩余等待时间，保持原 ID，不调用 provider。Begin 先通过账户 vault CAS 预留内部 Starting claim；执行期间 `current` 报告 `step.kind: "starting"`。同一有效 claim 只有 CAS 获胜者调用 provider。派发前或已取得明确 provider 结果后的确定性 Begin 失败只回滚本次 claim；此前被替换且未过期的 Ready 步骤在容量允许时恢复，并发 CAS 或取消优先。每次推进也先领取轮次 claim；provider 结果还须经过第二次 CAS 才能发布下一步。凭据竞争、取消、过期或会话撤销可能使结果被丢弃。外部预留应自行设定期限，可使用宿主生成的稳定 `factor_id` 关联。Provider 的中间工作必须可安全放弃；只有最终账户 CAS 才激活因素。

每账户最多一个待注册项，绑定发起 SID，默认 5 分钟过期。再次 begin 可替换准备中或已过期轮次，不会改变已生效因素。省略 `replace_factor_id` 表示新增，同一提供者可注册多个独立实例。显式替换的目标必须属于同一账户及 provider；最终轮次原子安装新 ID 并删除旧实例，此前旧 verifier 继续有效。每账户最多 8 个因素，满额时仍允许替换。label 必须非空白、无控制字符，且不超过 128 个 UTF-8 字节。改名只更新 label，保留因素身份、现有会话和准备中的待注册项。

每次推进先用账户 vault CAS 领取当前轮次的唯一 claim，再调用 provider；同一 ID 不会重复派发。仅当 provider 保证注册尚未完成、私有轮次状态仍可使用时，错误响应才允许重试。超时或结果未知时保留 `starting` 或 `in_flight` claim，不自动重放。活跃 claim 期间新 `begin` 或其他 MFA 管理修改返回凭据冲突；`cancel` 可显式放弃在途 provider 调用，过期后也可用新 `begin` 替换。两种路径均不能让迟到结果激活因素。Begin 或非终态响应丢失后，只要该注册仍是当前项，同一 SID 可调用 `current` 取回 ID 与公开挑战／状态；`current` 也提供在途 ID 供取消。其他 SID、已过期或已完成的注册返回 `no_enrollment`。非终态成功后的旧 ID 不可重放。终态响应丢失后，应使用当前凭据重新认证，再读取因素状态。

最终注册激活、移除和重新生成恢复码会轮换策略 epoch，旧 token、refresh 和 WebSocket SID 随后均无法通过复查。客户端应使用返回的新会话，并重新建立 WebSocket 认证连接。

所有凭据变更默认要求 5 分钟内的认证；已有独立因子时还要求 level 2。第一个因子允许近期主认证会话绑定，避免初始化死锁。refresh 不会刷新认证时间；超出窗口后需要重新登录，或通过 step-up 提交新的已绑定因子证明。Passkey 注册使用相同的近期认证检查。

最终注册激活、因子移除和恢复码重发所返回的新会话均完整保留原证据。会话元数据分开 `issued_at`（本次会话签发时间）与派生的 `authenticated_at`（最近实际验证时间），数量限制按 `issued_at` 淘汰。首因素激活不会升级会话；level 1 会话执行 level 2 操作前，须通过 step-up 提交真实因素证明或恢复码。删除最后一个因素也不降低历史证据。

Provider 异步工作结束后，服务在提交前重新验证 bearer、账户关联和近期窗口；Passkey 注册在最终写入边界同样重复检查；Passkey 注册、登录和因素最终激活还须在凭据写入前再次检查原注册期限。

TOTP 遵循 RFC 6238，支持 SHA1/256/512、6/8 位、可配置周期和有界时钟偏差；新注册默认使用 HMAC-SHA-256 和 32 字节随机秘密。配置随绑定保存，宿主配置修改只影响后续绑定。成功使用的时间步持久化，同一步或更早时间步不可重用。首因子激活返回 10 个各含 32 字节随机量的恢复码，只持久化 hash。登录或 step-up 使用 `{"kind":"recovery_code","code":"..."}`；每码只能消费一次，重新生成立即作废全部旧码。

`state://vault/console/credentials/<authority_id>/<instance_id>` 的有界聚合记录保存密码 hash、公钥、Passkey verifier、第二因子、待注册状态、重放状态及恢复码 hash。先 CAS 提交消费，再签发会话。同一 TOTP 时间步或恢复码最多成功消费一次；自定义 provider 须兑现自身的时效和防重放契约。签发前复查账号启用状态和策略 epoch。无效证明同时计入来源、账户及全局退避，以及持久化账户锁定。

凭据 DTO 的 Debug、审计和安全错误投影均不输出证明、注册输入、绑定 secret、恢复码、continuation token、交互载荷或 bearer。

凭据行和共享挑战账本均使用精确路径有界 State 点读及有界条件 CAS。嵌入 Console 的宿主必须在同一当前值提交域安装 `StateBoundedRead` 和 `StateBoundedWrite`；缺少端口时认证操作明确失败，不退回无界 State 读写。凭据内部 JSON 最多 256 KiB，使用宿主提供的 AES-256-GCM-SIV 密钥密封；带版本的密文信封以规范 base64url 编码存为 State 字符串，认证附加数据绑定用途、版本、authority、账户实例和密钥 ID。宿主须将同一个 `CredentialSealer` 提供给 root 初始化与 `ConsoleConfig.auth.credential_sealer`；缺少密钥、旧明文或格式错误的密文均拒绝读取。挑战账本内部 JSON 最多 4 MiB。编码后 State 行预算分别为 397,312 字节和 8,392,704 字节。并发替换成超大行时，CAS 在同一事务内拒绝；单行预算不限制保留的 State 历史。

Rust 宿主通过 `ConsoleConfig.auth.mfa.providers` 注册 `Arc<dyn MfaProvider>`。Provider 的 `descriptor()` 每次宿主装配只读取并校验一次，随后与实现共同保存；该宿主的 `provider_id`、声明中的 schema 和能力保持固定；挑战响应 schema 由 provider 逐轮提供并校验。端口分开以下操作：

| 方法 | 契约 |
| --- | --- |
| `begin_enrollment` | 接收借用的 provider 专属输入，返回含公开进度和私有轮次状态的 `MfaEnrollmentStep::Challenge` 或 `Pending`；首轮结果发布前的外部准备必须可安全放弃 |
| `continue_enrollment` | 用 `MfaInteractionInput::Response` 或 `Poll` 推进获授权的轮次，返回下一步骤或含待激活 verifier 的 `Verified` |
| `verify_proof` | 验证一次直接认证 proof，返回下一版 verifier |
| `begin_authentication` | 针对选定的活跃 verifier 开始交互 |
| `continue_authentication` | 用 `MfaInteractionInput::Response` 或 `Poll` 推进保存的私有状态 |

trait 默认方法返回 `MfaProviderError::Unavailable`，provider 应只声明已实现能力。Console 在调用前拒绝未声明操作；已声明方法在执行中返回 `Unavailable` 属于 provider 运行期故障，与安装、能力及使用准入分开。宿主提供的 `MfaContext` 包含不可变 `account_id`、`factor_id`、username、显示 label、`purpose` （`Enrollment`、`Login` 或 `StepUp`）、issuer 和时间；label 可修改，不能作为安全身份。宿主统一负责注册、CAS、恢复码和会话策略。Provider 调用有 10 秒超时，实现方负责独立性、时效、防重放及取消处理；每个实例分别保存重放状态，CAS 不能让不变的 verifier 自动具备防重放能力。交互调用还取得 `MfaInteractionContext`：已验证的因素上下文、稳定 `ceremony_id`、从 1 开始的调用 `round` 和原 `expires_at`，这些字段不来自客户端 JSON。注册调用则接收 `MfaEnrollmentContext`，包含同样稳定的流程身份、轮次和期限。

交互 provider 返回 `MfaInteractionStep::Challenge { private_state, challenge, response_schema }`、`Pending { private_state, status, retry_after_ms }` 或 `Verified { next_verifier }`。公开的 `AuthenticationStep::Challenge` 包含挑战和该轮的 `response_schema`；等待状态也公开。私有状态保留在 challenge ledger。Challenge 接受响应，Pending 接受轮询。`Verified` 不是会话：服务必须先取得 continuation 最终消费权，再提交账户 verifier CAS。选定 verifier 必须仍然匹配，不能覆盖另一认证已经推进的重放状态。Provider JSON 限制为 16 KiB、深度 32；schema 描述互操作输入，协议语义由 provider 校验。宿主不远程获取 schema，也不执行 provider 提供的客户端代码。

因素选择和 provider 轮次共用 challenge ledger 的数量与字节限额。claim 通过 CAS 将条目标记为在途并保留容量，多个调用不能分叉执行。后继轮换 opaque token，保持原截止时间，且继续受账本字节限制。默认认证期限为 120 秒，最多调用 provider 16 次（含 begin），最小轮询间隔 500 毫秒；上下界见 [MFA 配置](configuration.md#mfa-provider-安装)。每次 provider 调用同时受 10 秒超时及认证剩余时间限制。通过准入的过早轮询不消耗步数，也不计为无效 proof；当前 provider 使用策略、普通准入及账户锁定检查均在返回等待结果前执行。

轮次在途时，当前 token 仍可请求取消；取消与后继发布或最终消费竞争同一个账本 CAS。取消获胜后，该结果不能发布或提交凭据。条目继续占用配额，直到 provider 调用结束并回收条目，或原期限到期允许回收。最终消费获胜后，取消不能撤销凭据／会话提交或远端效果。不恢复或重试崩溃的在途 Future，其预留保留到原期限；后继响应丢失需要重新开始认证。

`ConsoleConfig.auth.mfa.install_totp` 默认为 `true`；设为 `false` 后可选择空安装或完全由 Rust 宿主提供实现。未安装的内置参数不执行 TOTP 组合校验，配置仍须使用合法字段类型和算法名称。最多安装 32 个 provider，按实际实现数量计数，与账户因素上限独立。重复的已安装 ID 会使装配失败；关闭内置 TOTP 后，可以在 `totp` ID 下显式安装兼容实现。复用任何已保存的 provider ID 都要求能识别其原 verifier 格式。

Provider 名称不选择账户恢复路径。`MfaProof::Factor` 从保存的因素解析已安装 provider，`MfaProof::RecoveryCode` 则直接消费账户恢复码；名为 `recovery_code` 的 provider 也不能截获这个独立证明分支。卸载 provider 保留其因素并标记不可用，不会降低账户的因素要求；已有恢复码仍可独立使用。Provider 是可信宿主代码，不能经请求或 daemon TOML 注入。自定义提供者可以自行完成硬件挑战、多轮响应和外部审批，分别使用注册与认证交互端口。这是扩展契约，不是内置推送服务或设备集成。TOTP 和恢复码保留直接证明；Passkey 主认证继续使用专门的 WebAuthn RP/origin 与 user verification 路径。

Provider 调用、vault CAS、会话和审计写入不构成分布式事务。响应丢失时，证明可能已经消费，绑定可能已经生效；应核对状态或重新认证，不能假定证明仍可使用。返回的恢复码与已配置 Passkey 之外的账户恢复属于显式宿主配置流程，不提供匿名重置入口。
