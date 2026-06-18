# HTTP Inference Providers

HTTP inference provider support lives behind the standard Provider inference
effects:

```text
effect://inference/infer
effect://inference/plan
effect://inference/embed
effect://inference/rerank
```

The backend translates those effects to one HTTP inference API dialect. The
supported dialects are:

- OpenAI Responses
- OpenAI Chat Completions
- Anthropic Messages
- Gemini GenerateContent

The dialect describes the HTTP API shape. OpenAI-compatible services such as
DeepSeek, OpenRouter, vLLM, and Ollama-compatible deployments can use the
OpenAI Chat Completions dialect with their own base URL and model id.

## Cargo Features

HTTP inference provider code is opt-in.

Use `http-inference` to enable all HTTP inference dialects, or enable only the
dialects a binary needs:

```toml
nexus-standard = {
  path = "crates/nexus-standard",
  default-features = false,
  features = ["standard", "openai-chat"],
}
```

`nexus-daemon` forwards the same feature names:

```text
cargo run -p nexus-daemon --features openai-chat
```

Available feature flags:

- `http-inference`
- `openai-responses`
- `openai-chat`
- `anthropic-messages`
- `gemini-generate-content`

## Runtime State

HTTP inference provider configuration is runtime state, managed through Console
Protocol actions:

```text
state://kernel/inference/backends/<backend_id>
state://kernel/inference/models/<model_id>
state://kernel/inference/groups/<group_name>
state://kernel/routing/inference
```

Use `inference.backend.*`, `inference.model.*`, `inference.group.*`, and
`inference.routing.*` to read, list, and write these declarations. The fixed
actions use the same kernel config admission path as external installations and
manifests. Generic `config.*` actions reject these runtime config paths.
Unknown `state://kernel/*` config paths are rejected.

The backend record declares the API dialect, base URL, optional API version,
non-secret headers, and secret references. The model record declares the
provider model id and the methods and modalities it supports. Groups and
routing select the default model set, fallback, retry count, and group policy.
Set `api_version` only for dialects that define a version header; currently
this is used by Anthropic Messages. `max_retries` is capped at `8` by
admission.

The model record id is the `models/<model_id>` path id. Runtime route results
use the qualified model id `<backend_id>/<model_id>`.

Embedding results include the embedding model and a `space_id`. The default
space id is `http-inference/<backend_id>/<embedding_model>`, so vectors from
different backends are not mixed during retrieval.

Example backend declaration:

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

Example model declaration:

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

When an HTTP inference provider feature is enabled, inference calls require
runtime provider state. Missing inference state is an error. Builds without HTTP
inference provider features use the offline baseline backend.

## Boundaries

HTTP inference providers send plain text requests today. `Blob`, `Tensor`, `Frame`,
and inline bytes are rejected before HTTP.

Provider-native tool fields are rejected. Nexus tool execution must go through
Nexus effects and policy.

Request overrides can add non-secret provider fields. They cannot replace the
model id, message payload, streaming flag, auth fields, tool fields, system
fields, previous response ids, conversation ids, or safety settings.

Provider error bodies are truncated and configured auth material is redacted
before the error is returned.
