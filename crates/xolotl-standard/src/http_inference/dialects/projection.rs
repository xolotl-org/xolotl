//! Fields consumed by each protocol. Provider extensions remain parseable but
//! never become resident JSON merely because they appeared on the wire.

use crate::http_inference::config::HttpInferenceDialect;
use crate::http_inference::json::project::{NUMBER, Rule, TEXT};

static TEXT_PART: Rule = Rule::Object(&[("text", &TEXT)]);
static TEXT_PARTS: Rule = Rule::Array {
    item: &TEXT_PART,
    first: false,
};
static CONTENT: Rule = Rule::Object(&[("parts", &TEXT_PARTS)]);
static OPENAI_USAGE: Rule =
    Rule::Object(&[("prompt_tokens", &NUMBER), ("completion_tokens", &NUMBER)]);
static USAGE: Rule = Rule::Object(&[("input_tokens", &NUMBER), ("output_tokens", &NUMBER)]);
static ERROR: Rule = Rule::Object(&[("message", &TEXT)]);

static RESPONSES_UNARY: Rule = Rule::Object(&[
    ("output_text", &TEXT),
    (
        "output",
        &Rule::Array {
            item: &Rule::Object(&[("content", &TEXT_PARTS)]),
            first: false,
        },
    ),
]);
static CHAT_UNARY: Rule = Rule::Object(&[(
    "choices",
    &Rule::Array {
        item: &Rule::Object(&[("message", &Rule::Object(&[("content", &TEXT)]))]),
        first: true,
    },
)]);
static ANTHROPIC_UNARY: Rule = Rule::Object(&[(
    "content",
    &Rule::Array {
        item: &Rule::Object(&[("type", &Rule::Tag(&["text"])), ("text", &TEXT)]),
        first: false,
    },
)]);
static GEMINI_UNARY: Rule = Rule::Object(&[(
    "candidates",
    &Rule::Array {
        item: &Rule::Object(&[("content", &CONTENT)]),
        first: true,
    },
)]);

static OPENAI_EMBEDDING: Rule = Rule::Object(&[(
    "data",
    &Rule::Array {
        item: &Rule::Object(&[(
            "embedding",
            &Rule::Array {
                item: &NUMBER,
                first: false,
            },
        )]),
        first: true,
    },
)]);
static GEMINI_EMBEDDING: Rule = Rule::Object(&[(
    "embedding",
    &Rule::Object(&[(
        "values",
        &Rule::Array {
            item: &NUMBER,
            first: false,
        },
    )]),
)]);

static RESPONSES_STREAM: Rule = Rule::Object(&[
    ("error", &ERROR),
    (
        "type",
        &Rule::Tag(&[
            "response.output_text.delta",
            "response.completed",
            "response.incomplete",
            "response.failed",
        ]),
    ),
    ("delta", &TEXT),
    ("response", &Rule::Object(&[("usage", &USAGE)])),
]);
static CHAT_STREAM: Rule = Rule::Object(&[
    ("error", &ERROR),
    ("usage", &OPENAI_USAGE),
    (
        "choices",
        &Rule::Array {
            item: &Rule::Object(&[
                ("delta", &Rule::Object(&[("content", &TEXT)])),
                ("finish_reason", &Rule::Tag(&["length"])),
            ]),
            first: true,
        },
    ),
]);
static ANTHROPIC_STREAM: Rule = Rule::Object(&[
    ("error", &ERROR),
    ("type", &Rule::Tag(&["content_block_delta", "message_stop"])),
    (
        "delta",
        &Rule::Object(&[
            ("text", &TEXT),
            ("stop_reason", &Rule::Tag(&["max_tokens"])),
        ]),
    ),
    ("message", &Rule::Object(&[("usage", &USAGE)])),
    ("usage", &USAGE),
]);
static GEMINI_STREAM: Rule = Rule::Object(&[
    ("error", &ERROR),
    (
        "usageMetadata",
        &Rule::Object(&[
            ("promptTokenCount", &NUMBER),
            ("candidatesTokenCount", &NUMBER),
        ]),
    ),
    (
        "candidates",
        &Rule::Array {
            item: &Rule::Object(&[("content", &CONTENT), ("finishReason", &TEXT)]),
            first: true,
        },
    ),
]);

pub(in crate::http_inference) fn generation(dialect: HttpInferenceDialect) -> &'static Rule {
    match dialect {
        HttpInferenceDialect::OpenAiResponses => &RESPONSES_UNARY,
        HttpInferenceDialect::OpenAiChatCompletions => &CHAT_UNARY,
        HttpInferenceDialect::AnthropicMessages => &ANTHROPIC_UNARY,
        HttpInferenceDialect::GeminiGenerateContent => &GEMINI_UNARY,
    }
}

pub(in crate::http_inference) fn embedding(dialect: HttpInferenceDialect) -> &'static Rule {
    match dialect {
        HttpInferenceDialect::GeminiGenerateContent => &GEMINI_EMBEDDING,
        _ => &OPENAI_EMBEDDING,
    }
}

pub(in crate::http_inference) fn stream(dialect: HttpInferenceDialect) -> &'static Rule {
    match dialect {
        HttpInferenceDialect::OpenAiResponses => &RESPONSES_STREAM,
        HttpInferenceDialect::OpenAiChatCompletions => &CHAT_STREAM,
        HttpInferenceDialect::AnthropicMessages => &ANTHROPIC_STREAM,
        HttpInferenceDialect::GeminiGenerateContent => &GEMINI_STREAM,
    }
}
