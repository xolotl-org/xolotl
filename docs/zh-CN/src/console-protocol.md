# 控制台协议

Console 通过一套服务开放宿主选定的管理操作和运行时能力。Rust 宿主、HTTP 单次调用与 WebSocket 共用动作准入、授权、审计和执行；已准入的 `Operation` 仍由 Kernel 检查。客户端按描述符组合自己的工作流，发现结果不授予调用权限。

| 需求 | 页面 |
| --- | --- |
| 调用资源、运行可移植程序、提交保留结果或订阅 | [运行时调用与提交](console-runtime.md) |
| 挂载 HTTP、登录及管理主凭据和第二因子 | [HTTP 与凭据](console-http-and-credentials.md) |
| 使用 v1 帧、动作描述符、State/Fact 查询或审计流 | [动作与流](console-actions-and-streams.md) |
| 选择 daemon 监听器和传输 | [网关](gateways.md) |

## 服务边界

验证位于实际传输交接处，也覆盖适配器拥有的缓冲。在缓冲之后的可写或 flush 等待前检查并不足够。生产 WebSocket 会话拥有完整 socket，不使用 split sink，避免 split 适配器在验证与底层接纳之间插入另一次未检查的可写等待。自定义适配器须维持相同顺序。

已接纳的自身会话撤销动作之后，若读取 revision 元数据失败，原始错误和会话已失效的判定仍然保留；服务不得为已撤销 SID 安装交付 guard。停止交付受保护失败时，保留 `OutcomeUnknown` 分类、已知执行／未决身份及原生清理责任，不披露其受保护的 `runtime_completion`。交付被拒绝既不是回滚，也不是清理完成证明。

`ConsoleService::call` 与 `ConsoleCallAdmission::call` 是本地观察便捷入口：执行动作，并在向 Rust 调用者返回前验证结果的当前交付权限。网络适配器改用 `prepare_call`，取得不透明的 `PreparedConsoleResult`，其中保留动作结果或结构化失败。`into_parts` 分离本地结果与可选的 `ConsoleDelivery`；适配器须跨编码、排队及 socket 可写等待保留该 guard，并在向传输交出字节前调用 `ConsoleDelivery::validate`。`deliver` 只完成本地验证，不授权之后的延迟发送。验证不重复动作，不续期会话或可见性期限。明确撤销自身会话的控制确认不带 guard；这一例外不授权撤销后交付普通受保护结果。

`ConsoleState::with_config(boot, ConsoleConfig)` 构造共享服务状态，不启动监听器。`ConsoleService::new(state)` 提供认证、动作调用和订阅；调用方提交 bearer，服务重新验证会话并检查描述符和具体目标。宿主提供已验证的连接来源用于审计及传输策略，不能直接注入预授权 principal。拥有型 Rust `RuntimeRequest` 可经 `run_runtime`、`submit_runtime`、`subscribe_runtime` 进入服务；见 [Rust 运行时请求](console-runtime.md#rust-运行时请求)。

```rust,ignore
use xolotl_console::{ConsoleConfig, ConsoleService, ConsoleState};
use xolotl_console::session_store::{ConsoleSessionPolicy, MemoryConsoleSessionStore};
use std::sync::Arc;

let sessions = Arc::new(MemoryConsoleSessionStore::new(ConsoleSessionPolicy::default()));
let state = ConsoleState::with_config(boot, ConsoleConfig {
    session_store: Some(sessions),
    ..ConsoleConfig::default()
})?;
let service = ConsoleService::new(state);
```

`ConsoleConfig::default()` 不安装宿主配置校验器。嵌入宿主可为既有声明空间或自定义 `state://kernel/config/<owner>` 命名空间注册 `ConfigNamespaceAdmission`；stock daemon 在装配时安装 Gateway、manifest、projection 和 inference 的校验器。Console 仍负责授权、版本检查与 CAS。宿主配置写入若没有匹配的准入规则则失败；重叠或保留命名空间的声明会在装配时被拒绝。

默认 crate feature 提供嵌入服务及有界 wire codec，无需 Axum。启用 `http` 才包含 HTTP/WebSocket 适配器。同一 `ConsoleState` 的适配器共享认证、注册表、调用及订阅准入、提交执行的生命周期。各 `HttpState` 持有自己的 Origin、代理、连接及帧交付策略；WebSocket 管理帧交付与连接队列。自定义适配器先验证连接与来源，再在收取或解码调用帧前调用 `ConsoleService::admit_call()`。返回的 `ConsoleCallAdmission` 借用签发它的服务、不可克隆；帧损坏或请求取消时直接丢弃便会释放容量。解码成功后以 `admission.call(bearer, source, action)` 消费许可。许可还提供 `run_runtime` 和 `submit_runtime` 来提交拥有型 Rust 请求；直接 service 方法也使用相同的准入与分发路径。帧大小、正文期限及来源证明仍由适配器负责；编码见[动作与流](console-actions-and-streams.md#编码)。

Rust 宿主可在 `ConsoleConfig` 安装 `ExternalPrimaryAuthentication` 和 `AccountAuthority`：前者验证主证明，后者提供当前账户，Console 发行自己的 bearer。宿主账户模式下，本地主登录关闭。

Daemon 默认将 Console 挂载在 `/api/console/v1`。Rust 宿主可选择相对 HTTP 路由并挂载到其他路径；详见[HTTP 路由](console-http-and-credentials.md#http-路由)。

运行时成功回复与经安全投影的错误都可独立携带 `unresolved_operations`，其中 `operation_ids` 是宿主观察到的有界、有序 ID；若未能保留全部身份，`identities_incomplete` 为 true。因此成功值也可能需要外部核对。v1 protobuf 的回复与错误帧保留同一字段；调用方决定是否重新发起效果前应先检查它。保留执行的查询规则见[独立提交与结果保留](console-runtime.md#独立提交与结果保留)。

经安全投影的失败还可在 JSON 与 v1 protobuf 错误中携带 `runtime_completion`，在生命周期或交付失败后保留有界已知正文及独立清理投影。`body_retention_failure` 区分正文省略与效果未知。原生 `ConsoleFailure.finalization_error` 不编码，只为可信 Rust 宿主保留类型化原因和清理 ticket。投影状态、字节限额与重试责任见[独立提交与结果保留](console-runtime.md#独立提交与结果保留)。
