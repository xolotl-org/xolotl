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

Embedded hosts do not have to use HTTP inference. They can install
`xolotl-standard` with `StandardConfig::with_inference_backend` and supply an
in-process backend implementing `InferenceBackend`. That backend serves the same
`effect://inference/*` resources and the standard model-backed effects while
still being invoked through handles, policy, budget, and Facts.

## Cargo Features

HTTP inference provider code is opt-in.

Use `http-inference` to enable all HTTP inference dialects, or enable only the
dialects a binary needs:

```toml
xolotl-standard = {
  path = "crates/xolotl-standard",
  default-features = false,
  features = ["standard", "openai-chat"],
}
```

`xolotl-daemon` forwards the same feature names:

```text
cargo run -p xolotl-daemon --features openai-chat
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

## Embedding Values

The bundled dense embedding backends return an inline value:

```json
{
  "representation": {"kind": "dense", "values": [0.25, -0.5, 1.0]},
  "space_id": "http-inference/example/embedder",
  "embedding_model": "embedder"
}
```

The default HTTP space id is
`http-inference/<backend_id>/<embedding_model>`, so vectors from different
backends are not mixed during retrieval. Producing this value requires no object
store upload and returns no `TensorRef`. `InferenceBackend::embed` retains its
`Value` return type; custom backends can return other representations for
consumers that support them.

HTTP adapters preserve parsed `f64` vector values. The built-in vector index
stores and searches `f32` vectors, so indexing rounds values to `f32` and rejects
non-finite or out-of-range components. An embedding value can be passed directly
to `effect://index/search` once its space exists; add an `id` to use it with
`effect://index/upsert`.

For a stored tensor, explicitly pass the embedding's `representation.values` as `data` to the
installed `effect://tensor/write` resource:

```json
{
  "data": [0.25, -0.5, 1.0],
  "dtype": "f64"
}
```

`dtype: "f64"` preserves the inline values. Omitting `dtype` selects `f32`, which
rounds them on serialization. The tensor writer commits the bytes to its object
store before returning a `TensorRef` with the stored content hash, dtype, and
shape. This complete reference describes the view; different views can share
the same blob hash. The writer does not create a State catalog entry. Pass the
complete `TensorRef` or `FrameRef` value directly to the independently installed
`effect://blob/read` or `effect://blob/delete` capability; explicitly passing
`TensorRef.blob` also remains supported. These operations act on shared bytes,
and deleting content affects every view backed by that blob. For persistent
names, explicitly store the complete `TensorRef` at an application-selected
State path.

The default shape is `[data.len()]`. Explicit `shape: []` requires one value and
produces a scalar; a shape with a dimension of length zero requires empty `data` and
produces an empty tensor. See [Tensor Views](api-reference.md#tensor-views) for
examples and the object lifecycle.

The embedding envelope selects a representation explicitly. Retrieval consumers
admit that representation and its space before use; a tensor representation
requires an explicitly installed object reader.

## Incremental HTTP Data

Requests are encoded as the HTTP client pulls body windows, retaining shared
input and override values. Long strings, nested values and typed override
metadata do not require a complete request buffer. HTTP/1.1 uses chunked request
transfer when no length is supplied; no producer thread or additional queue is
created. Cancellation drops the body cursor with the request.

Unary and SSE responses share incremental JSON syntax validation and finite
provider field selection. Unknown keys, long strings and nested extensions are
validated without retaining their contents. Final unary text and vectors are
materialized; each SSE record retains only selected deltas and control fields
until full record validation, then yields under the existing output backpressure.
The optional `response_limits` policy applies to that selected materialization;
`io_window_bytes` controls work windows independently. See
[Configuration](configuration.md) for the fields and defaults.
Validated text deltas are then split into window-sized output chunks at UTF-8
boundaries; a complete scalar can exceed a window smaller than four bytes.

| Dialect | Consumed streaming text | Completion |
| --- | --- | --- |
| OpenAI Chat Completions | First choice's `delta.content` | `[DONE]` |
| OpenAI Responses | `response.output_text.delta` | Completed or incomplete event |
| Anthropic Messages | `content_block_delta.delta.text` | `message_stop` |
| Gemini GenerateContent | First candidate's text parts, as deltas | `STOP` or `MAX_TOKENS` |

OpenAI Responses cumulative completion content is skipped because the delta
stream already supplies its text; a growing snapshot does not enlarge retained
projection data. These adapters do not guess whether repeated provider text
means an append, a snapshot or a replacement. A provider whose consumed text is
a cumulative or replaceable snapshot needs an explicit protocol adapter and
matching consumer semantics. Selected unary output and a selected atomic SSE
delta still require materialization; no disk staging or partial-record delivery
mode is implied.

## Boundaries

HTTP inference providers send plain text requests today. `Blob`, `Tensor`, `Frame`,
and inline bytes are rejected before HTTP.

Provider-native tool fields are rejected. Xolotl tool execution must go through
Xolotl effects and policy.

Request overrides can add non-secret provider fields. They cannot replace the
model id, message payload, streaming flag, auth fields, tool fields, system
fields, previous response ids, conversation ids, or safety settings.

Provider error bodies are truncated and configured auth material is redacted
before the error is returned.
