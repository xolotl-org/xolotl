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
`StandardConfig::with_inference_backend` 安装 `andrias-standard`，并提供实现
`InferenceBackend` 的进程内 backend。这个 backend 仍服务同一组
`effect://inference/*` 资源和标准模型类 effect，并继续经过 handle、policy、budget 和 Fact。

## Cargo feature

HTTP 推理 Provider 代码需要显式启用。

启用全部 HTTP 推理 dialect：

```toml
andrias-standard = {
  path = "crates/andrias-standard",
  default-features = false,
  features = ["standard", "http-inference"],
}
```

也可以只启用需要的 dialect：

```toml
andrias-standard = {
  path = "crates/andrias-standard",
  default-features = false,
  features = ["standard", "openai-chat"],
}
```

`andrias-daemon` 转发同名 feature：

```text
cargo run -p andrias-daemon --features openai-chat
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

embedding 结果会带上 embedding model 和 `space_id`。默认 `space_id` 是
`http-inference/<backend_id>/<embedding_model>`，避免检索时混用不同 backend 产出的向量。

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

## 边界

当前 HTTP 推理 Provider 发送纯文本请求。`Blob`、`Tensor`、`Frame` 和 inline bytes
会在 HTTP 请求前被拒绝。

请求中的 provider tool 字段会被拒绝。工具调用必须通过 Andrias effect 和策略执行。

`request_overrides` 只能添加非敏感的 provider 字段。它不能替换 model id、消息
payload、streaming 标志、认证字段、tool 字段、system 字段、previous response id、
conversation id 或 safety settings。

provider 错误响应会被截断，配置中的认证材料会先脱敏再返回。
