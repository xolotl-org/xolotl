# 配置

`nexus.toml` 是引导配置。它控制存储、监听地址、root 引导凭据，以及有界的控制台资源限制。

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

`[server]` 设置控制台、gRPC 和 WebSocket 绑定地址。对应配置字段缺失时，
`nexusd` 还会读取 `NEXUS_CONSOLE_ADDR`、`NEXUS_GRPC_ADDR` 和
`NEXUS_WS_ADDR`。配置字段和环境变量都缺失时，该监听地址保持关闭。gRPC
监听地址来自默认构建启用的 `grpc` feature。

`[console.root]` 可预置 root 凭据。

`[console.auth]` 设置会话 TTL、会话数量和 Argon2 校验并发限制。

`[console.ws]` 设置控制台 WebSocket 的帧大小、连接数、空闲时间、速率、订阅数、结果大小和事件背压限制。

## 运行时配置

运行时提供方设置、模型路由、组、绑定和受策略管理的状态都属于 Nexus 状态，并通过控制台网关管理。

控制台认证和 WebSocket 设置属于部署容量参数。能力检查、二次确认门槛、Origin/Host 校验、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。
