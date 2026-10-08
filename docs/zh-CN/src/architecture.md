# 架构

Xolotl 是可嵌入、可组合的能力运行时。目标是**高通用性、高性能和高内存效率**，同时满足安全与真实的效果／数据提交语义。应用拥有业务政策；宿主选择资源、存储、调度和开放范围。

```text
本地 SDK                        远端客户端
    |                                |
    |                            协议适配器
    |                                |
    |                             服务准入
    +---------------+----------------+
                    |
                    +-- 程序 --> 编译器 --> Core --+
                    |                    请求／完成|
                    +-- 直接调用 -----------------+
                                                  v
                                 Kernel: Process / Handle / 策略
                                                  | 已准入 Operation
                                                  v
                                        Driver -> 结果／来源／用量

宿主装配端口、预算和任务生命周期。
数据及服务存储拥有各自的提交与留存。
```

Core 推进控制流、取消和词法清理。Kernel 授权资源调用，Driver 执行效果。服务接纳客户端并开放选定能力；适配器处理传输。可信组件之间传递普通类型化值，保护措施放在实际信任边界，见[安全政策](security-and-boundaries.md)。

## 分层与代码归属

| 所有者 | 职责 | 依赖方向 |
| --- | --- | --- |
| `xolotl-types` | 值、来源、标识与未决操作证据 | 可移植表示，独立于服务政策 |
| `xolotl-core` | 控制流及请求／完成转换 | 泛型值与调用方存储，不依赖领域 crate |
| `xolotl-plan`、`xolotl-graph` | 有界编译到 Core 程序 | Types 与 Core；执行归运行时 |
| `xolotl-kernel` | 调用、Process 权限、Handle、本轮执行与宿主端口 | Core 与数据合同 |
| `xolotl-state`、`xolotl-source` | 观察／历史；外部安装与流证据 | 数据合同，由存储适配器实现 |
| `xolotl-storage-*` | 事务、索引、留存计量与后端恢复 | 数据及可选服务存储合同 |
| Gateway、Console、Federation | 客户端准入、开放范围、服务记录与交付权限 | Kernel／数据端口；适配器使用服务合同 |
| 协议适配器 | 帧、连接证据、缓冲与传输交接 | 服务判断仍归服务 |
| Standard、SDK、daemon | 资源实现、嵌入门面、宿主装配与关闭 | 组合下层，规则仍归所属所有者 |

按需要选择执行配置：

| 需求 | 入口 | 宿主提供 |
| --- | --- | --- |
| 无堆分配的控制流 | Core；SDK 默认 `core` | 机器存储及请求／完成处理 |
| 可移植编译 | SDK `program` | 程序输入与编译限额 |
| 协作式执行 | SDK `runtime` | 调用方存储、调用与调度端口 |
| 托管执行 | SDK `host` | 资源、权限、HostRuntime 与选定后端 |
| 远程接入 | 服务及协议适配器 | 托管运行时、客户端准入与开放范围 |

Core-only 宿主自行处理效果。Kernel 的可移植 runtime 与托管配置有不同装配要求；`host` 引入基于 Tokio 的集成。见[feature 组合](core-and-portable.md#feature-组合)。

## 从声明到效果

1. 宿主安装 Resource 与 Interface，向 Process 委派授权。
2. `open()` 解析方法，将固定的方法契约和 Driver 计划编译为进程专属 Handle。Registry 变更不改写已有句柄。
3. 直接调用与程序请求经过同一分派边界：Kernel 在调用 Driver 前检查所有者、存活状态、方法权限及当前剩余策略。
4. Driver 返回结果、来源与用量；Kernel 结算预算，并按选择记录诊断 Fact。
5. 执行完成词法清理，所属服务结算请求记录；适配器在最终传输交接时检查当前披露权限。

效果完成、服务记录结算和字节交付是不同事实。Signal 等待通过已授权的 `subscribe` Operation 接入。见[运行时模型](runtime-model.md)、[能力模型](capability-model.md)和[程序与重放](programs-and-replay.md)。

## 宿主组合

`KernelBuilder` 选择端口、身份来源和限额，创建相互关联的运行表；`build()` 不启动任务或监听器。`Bootstrap::from_kernel` 建立根 Process，`Xolotl::from_kernel` 增加 SDK 门面。编译 feature、安装 Resource、授予权限是独立的宿主选择。

同一 Kernel 的 clone 共享表与端口；独立 builder 创建独立运行域，即使共用后端。组件须属于预期运行域；共享执行命名空间的宿主也共享 `ExecutionIdSource`，持久调用者身份保留签发它的 `IdentityDirectory`。Fact 观察默认关闭；默认执行 ID 来源使用新的内存命名空间。

宿主拥有已安装的效果 runtime 与已接纳任务，直到清理完成。关闭时先关闭准入、停止生产者，等待所拥有任务并 drain 已接纳工作，再释放存储。关闭等待被中断或有多个等待者时，仍保留这些责任。见[装配 API](api-reference.md)和[本轮执行与持久化](core-and-portable.md#本轮挂起与数据持久化)。

## 状态、提交与证据

| 信息 | 所有者与含义 |
| --- | --- |
| 帧、Process／Handle 表、在途调用 | 本轮宿主生命周期；本轮挂起保留正在运行的工作 |
| State、Source 位置、对象、凭据 | 各自数据所有者；持久化保存数据，不保存普通执行 |
| 服务请求记录 | 所属服务／存储；在声明范围内表达受理、重试及对账 |
| 未决操作证据 | 可信本地调用标识；跨被处理错误与竞争失败分支保留 |
| Fact 与 trace | 可选观察，区别于权限和提交证据 |

各数据所有者独立提交。独立逻辑域可能共享后端恢复边界：不确定提交可能要求重开共享实例。宿主先遵循后端的拒绝与释放合同，再对账。

分派前取消可以阻止工作。外部效果开始后，取消、传输丢失或停止输出不证明回滚。程序成功结果不清除未决效果；远端判定仍是对端声明，不成为可信本地操作标识。

证据查询、缓存结果交付与执行是独立操作。证据缺失既不证明未提交，也不允许安全重放。重试范围包含证据所有者的命名空间和合同版本；只有可信宿主先关闭范围，再回收满足条件的证据。留存责任跨配置及 feature 变化继续成立。

State 通知是实时观察，不是持久事件日志；Fact 扫描不恢复程序。提交、重试和留存细节由下列所属合同维护。

## 跨层组合检查

每次异步交接或跨所有者调用，明确：

1. **权限**：分派或披露时使用哪个身份、合同与依赖？受保护的排队输出保留原权限与期限，直到最终传输交接。
2. **责任**：取消或断连后，谁拥有已接纳工作、未决效果和清理？
3. **提交**：哪个域已知、被拒绝或仍不确定，什么证据标识它？回复或队列接纳不证明对端收取。
4. **容量**：工作前计量什么，在哪里留存，预留如何移交？准备、在途工作和留存数据有不同成本。
5. **释放**：什么可观察事件确认资源已释放，包括清理失败或关闭中断时？

容量费用保留到实际释放。共享配额须允许已接纳工作增量完成；独立实例限额不会自动组成宿主总预算。编码字节、结构工作与留存内存是不同计量，任何一项都不能单独限制 RSS 或原生 Driver 分配。先考虑删除工作或复用所有者，再增加注册表、历史或包装。

## 外部入口

[应用网关](application-gateway.md)开放 profile 约束的业务调用；[External Gateway](external-gateway.md)安装远端 Provider 和 Source；[Console](console-protocol.md)开放选定管理与运行操作。它们的准入政策不同，委派的 Operation 都保留 Kernel 检查。服务及传输选择见[网关](gateways.md)。

可选 Federation 提供已认证节点 Session、限定范围的流补读、对象与远端调用。宿主提供路由、主体映射、应用投影及合并规则。`path://<cluster>/...` 名称本身不提供连接或权限，Kernel Process 留在本地。联邦提交判定及最终交付检查归服务／传输合同，不从错误文本或本地执行证据推导。

按规则所有者继续检查：

| 细节 | 主要合同／指南 |
| --- | --- |
| 编译、缓冲、本轮调度与取消 | [核心与可移植程序](core-and-portable.md) |
| State／Fact 端口及后端恢复 | [状态与事实记录](state-and-facts.md) |
| Gateway 证据、结果交付与重试关闭 | [应用网关](application-gateway.md)、[请求存储合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-gateway/src/idempotency_store.rs) |
| Console 受理、认证与交付 | [Console 运行模型](console-runtime.md)、[Console 协议](console-protocol.md) |
| Source 决策时间与只读检查 | [Source 合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs) |
| Federation 留存、快照、调用时钟与披露 | [Federation 合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs)、[传输合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation-grpc/src/lib.rs)、[配置](configuration.md#联邦发布端) |
| 标准 Driver 保证及限额 | [API 参考](api-reference.md)、[配置](configuration.md) |

先读所属公开 rustdoc，再读实现和验收测试。跨层决策放在本页，领域转换、字段清单和算法细节放在所属合同。
