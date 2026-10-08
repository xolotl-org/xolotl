# Xolotl 手册

Xolotl 是可嵌入、可组合的能力运行时，目标是高通用性、高性能与高内存效率。应用拥有业务；宿主选择资源、存储、调度与开放范围。本手册说明嵌入方式、可选服务与宿主配置。

先看[架构](architecture.md)，再通过[核心与可移植程序](core-and-portable.md)选择执行配置。托管执行进一步阅读[运行时模型](runtime-model.md)和[能力模型](capability-model.md)。处理具体任务时，按下表查找：

| 任务 | 页面 |
| --- | --- |
| 将 Xolotl 嵌入 Rust 宿主或组合可移植程序 | [核心与可移植程序](core-and-portable.md)、[API 参考](api-reference.md) |
| 运行并配置 `xolotld` | [配置](configuration.md) |
| 调用应用 surface | [应用网关](application-gateway.md) |
| 通过 Console 管理运行时 | [控制台协议](console-protocol.md) |
| 接入外部 Provider 或 Source | [External Gateway](external-gateway.md) |
| 连接独立节点 | [联邦配置](configuration.md#联邦发布端)、[FederationStore 合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs) |
| 选择监听器或协议 | [网关](gateways.md) |
| 配置 HTTP 模型 Provider | [HTTP 推理 Provider](http-inference-providers.md) |
| 核对重放、状态或信任边界 | [程序与重放](programs-and-replay.md)、[状态与事实记录](state-and-facts.md)、[安全边界](security-and-boundaries.md) |

中英文术语对照见[术语表](glossary.md)。
