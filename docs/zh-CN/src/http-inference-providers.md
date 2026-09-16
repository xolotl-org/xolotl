# HTTP 推理 Provider

HTTP 推理 Provider 挂在标准 Provider inference effect 后面：

```text
effect://inference/infer
effect://inference/plan
effect://inference/embed
effect://inference/rerank
```

backend 会把这些 effect 转成一个 HTTP 推理 API dialect。当前支持：

- OpenAI Responses
- OpenAI Chat Completions
- Anthropic Messages
- Gemini GenerateContent

dialect 描述 HTTP API 形态。DeepSeek、OpenRouter、vLLM、Ollama 兼容部署等
OpenAI 兼容服务可以使用 OpenAI Chat Completions dialect，并配置自己的
`base_url` 和 `provider_model`。

嵌入式宿主不必使用 HTTP 推理。宿主可以用
`StandardConfig::with_inference_backend` 安装 `xolotl-standard`，并提供实现
`InferenceBackend` 的进程内 backend。这个 backend 仍服务同一组
`effect://inference/*` 资源和标准模型类 effect，并继续经过 handle、policy、budget 和 Fact。

## Cargo feature

HTTP 推理 Provider 代码需要显式启用。

启用全部 HTTP 推理 dialect：

```toml
xolotl-standard = {
  path = "crates/xolotl-standard",
  default-features = false,
  features = ["standard", "http-inference"],
}
```

也可以只启用需要的 dialect：

```toml
xolotl-standard = {
  path = "crates/xolotl-standard",
  default-features = false,
  features = ["standard", "openai-chat"],
}
```

`xolotl-daemon` 转发同名 feature：

```text
cargo run -p xolotl-daemon --features openai-chat
```

可用 feature：

- `http-inference`
- `openai-responses`
- `openai-chat`
- `anthropic-messages`
- `gemini-generate-content`

## 运行时状态

HTTP 推理 Provider 配置是运行时状态，通过 Console Protocol action 管理：

```text
state://kernel/inference/backends/<backend_id>
state://kernel/inference/models/<model_id>
state://kernel/inference/groups/<group_name>
state://kernel/routing/inference
```

使用 `inference.backend.*`、`inference.model.*`、`inference.group.*` 和
`inference.routing.*` 读取、列出和写入这些声明。固定 action 走与 external
installation 和 manifest 相同的 kernel config 准入。泛用 `config.*` action
会拒绝这些运行时配置路径。未知 `state://kernel/*` config path 会被拒绝。

backend 记录声明 API dialect、base URL、可选 API version、非敏感 header 和 secret
引用。model 记录声明 provider model id，以及它支持的方法和模态。group 和 routing
记录声明默认模型组、fallback、retry 次数和组策略。
只有定义了 version header 的 dialect 才能设置 `api_version`；当前用于 Anthropic
Messages。`max_retries` 准入上限是 `8`。

model 记录的 `id` 是 `models/<model_id>` 的路径 id。运行时 route 结果使用限定名
`<backend_id>/<model_id>`。

backend 声明示例：

```json
{
  "id": "deepseek",
  "dialect": "openai_chat_completions",
  "base_url": "https://api.deepseek.com",
  "auth": {
    "kind": "bearer_token",
    "token_ref": "state://vault/inference/deepseek/api_key"
  },
  "default_headers": {},
  "request_overrides": {},
  "api_version": null,
  "version": 1
}
```

model 声明示例：

```json
{
  "id": "deepseek-chat",
  "backend_id": "deepseek",
  "provider_model": "deepseek-chat",
  "capabilities": {
    "methods": { "infer": true, "embed": false, "rerank": false, "plan": true },
    "modality": 1,
    "tools": false,
    "vision": false,
    "audio": false,
    "json": true,
    "streaming": false
  },
  "weight": 1,
  "version": 1
}
```

启用 HTTP 推理 Provider feature 后，inference 调用必须有运行时 provider 状态。缺少
inference 状态是错误。未启用 HTTP 推理 Provider feature 的构建使用离线 baseline
backend。

## Embedding 值

内置稠密 embedding backend 返回内联值：

```json
{
  "representation": {"kind": "dense", "values": [0.25, -0.5, 1.0]},
  "space_id": "http-inference/example/embedder",
  "embedding_model": "embedder"
}
```

HTTP 默认 `space_id` 是 `http-inference/<backend_id>/<embedding_model>`，
避免检索时混用不同 backend 产出的向量。生成这个值不需要上传对象存储，也不返回
`TensorRef`。`InferenceBackend::embed` 的返回类型仍是 `Value`；自定义 backend
可以返回其他表示，由支持该表示的组件消费。

HTTP adapter 保留解析后的 `f64` 向量数值。内置向量索引用 `f32` 存储和搜索，
因此写入索引时会舍入到 `f32`，并拒绝非有限数或超出范围的分量。目标空间存在后，
可以将 embedding 值直接传给 `effect://index/search`；添加 `id` 后可传给
`effect://index/upsert`。

需要存储张量时，显式将 embedding 的 `representation.values` 作为 `data` 传给已安装的
`effect://tensor/write` 资源：

```json
{
  "data": [0.25, -0.5, 1.0],
  "dtype": "f64"
}
```

`dtype: "f64"` 保留内联数值的精度。省略 `dtype` 时默认使用 `f32`，序列化时会
舍入。张量写入器将字节提交到对象存储后，才返回包含实际内容哈希、dtype 和 shape
的 `TensorRef`。完整引用本身描述视图，不同视图可以共享同一 blob 哈希。写入器
不创建 State 目录条目。可将完整 `TensorRef` 或 `FrameRef` 值直接传给独立安装的
`effect://blob/read` 或 `effect://blob/delete` 能力，也支持显式传入 `TensorRef.blob`。
这些操作针对共享字节，删除内容会影响使用该 blob 的所有视图。需要持久命名时，
显式将完整 `TensorRef` 保存到应用选择的 State 路径。

默认 shape 为 `[data.len()]`。显式 `shape: []` 需要一个值并生成标量；shape 中存在
长度为 0 的维度时，需要空 `data` 并生成空张量。示例和对象生命周期见[张量视图](api-reference.md#张量视图)。

embedding envelope 显式选择表示。检索消费者在使用前校验表示及其空间；张量表示需要显式安装的对象读取能力。

## HTTP 增量数据

HTTP 客户端拉取请求体时才编码一个窗口，游标持有共享的输入和 override 值。长字符串、
嵌套值以及 override 中的类型化元数据均不需要完整请求缓冲区。未提供长度时，HTTP/1.1
使用 chunked 请求传输；不创建生产线程或额外队列，取消请求会释放其编码游标。

Unary 和 SSE 共用增量 JSON 语法校验和有限的 Provider 字段选择规则。未知键、长字符串
及嵌套扩展字段在校验后直接跳过。最终 unary 文本和向量仍需物化；SSE 每条记录只保留
已选 delta 及控制字段，完整校验后再通过原有输出背压交付。可选 `response_limits` 管理
这些选中数据的物化，`io_window_bytes` 独立控制工作窗口。配置字段与默认值见
[配置](configuration.md)。
通过校验的文本 delta 随后按工作窗口分块交付，分块保持完整 UTF-8 字符；
当窗口小于四字节时，一个完整字符可能超过窗口大小。

| 方言 | 消费的流式文本 | 完成条件 |
| --- | --- | --- |
| OpenAI Chat Completions | 第一个 choice 的 `delta.content` | `[DONE]` |
| OpenAI Responses | `response.output_text.delta` | completed 或 incomplete 事件 |
| Anthropic Messages | `content_block_delta.delta.text` | `message_stop` |
| Gemini GenerateContent | 第一个 candidate 的 text parts，按 delta 解释 | `STOP` 或 `MAX_TOKENS` |

OpenAI Responses 完成快照的累计内容会被跳过，因为文本已经由 delta 流提供；快照增长
不会增加保留的投影数据。适配器不会根据文本重复猜测追加、累计快照或替换语义。
如果 Provider 的实际文本字段是累计或可替换快照，需要明确的协议适配器及匹配的消费契约。
最终 unary 输出和选中的原子 SSE delta 仍需要物化；当前没有隐含的磁盘暂存或半条记录交付模式。

## 边界

当前 HTTP 推理 Provider 发送纯文本请求。`Blob`、`Tensor`、`Frame` 和 inline bytes
会在 HTTP 请求前被拒绝。

请求中的 provider tool 字段会被拒绝。工具调用必须通过 Xolotl effect 和策略执行。

`request_overrides` 只能添加非敏感的 provider 字段。它不能替换 model id、消息
payload、streaming 标志、认证字段、tool 字段、system 字段、previous response id、
conversation id 或 safety settings。

provider 错误响应会被截断，配置中的认证材料会先脱敏再返回。
