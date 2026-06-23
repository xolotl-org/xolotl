//! Standard conversation message schema.
//!
//! All chat channels (team chat, CLI, web, etc.) serialise their messages
//! into this unified format so that Memory, TokenCompressor, and
//! AutoContext can operate on a single representation.
//!
//! The schema is stored as `Value::Map` on `state://chat/*/messages/*`.

use crate::BlobRef;
use serde::{Deserialize, Serialize};

/// Who authored this message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// System/developer instruction message.
    System,
    /// End-user message.
    User,
    /// Assistant/model message.
    Assistant,
    /// Tool message.
    Tool,
}

/// One content part inside a multi-modal message.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// Text content.
    Text {
        /// Text body.
        text: String,
    },
    /// Tool call requested by the assistant.
    ToolCall {
        /// Tool call id.
        id: String,
        /// Tool name.
        name: String,
        /// Tool arguments.
        arguments: crate::Value,
    },
    /// Tool result returned to the assistant.
    ToolResult {
        /// Tool call id being answered.
        id: String,
        /// Tool result payload.
        result: crate::Value,
    },
    /// Image content stored out of line.
    ImageRef {
        /// Referenced image blob.
        blob: BlobRef,
    },
    /// Opaque structured data passed through to the inference backend
    /// without interpretation (e.g. provider-specific cache-control hints).
    Opaque {
        /// Opaque part kind.
        kind: String,
        /// Opaque payload.
        payload: crate::Value,
    },
}

/// A single turn in a conversation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message author role.
    pub role: MessageRole,
    /// Ordered content parts.
    pub content: Vec<ContentPart>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// Source-system metadata such as sender id and channel.
    /// Never injected into the model prompt — only used for
    /// routing and audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ChatMetadata>,
}

/// Source-system metadata attached to every message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatMetadata {
    /// Source system name.
    pub platform: String,
    /// Source-system conversation or channel id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// Source-system sender or user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,
    /// Opaque extra fields the connector wants to carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<crate::Value>,
}

impl ChatMessage {
    /// Create a simple user text message with the given source metadata.
    pub fn user(
        platform: impl Into<String>,
        conversation_id: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![ContentPart::Text { text: text.into() }],
            timestamp: now_secs(),
            metadata: Some(ChatMetadata {
                platform: platform.into(),
                conversation_id: Some(conversation_id.into()),
                sender_id: None,
                extra: None,
            }),
        }
    }

    /// Create an assistant text response.
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: vec![ContentPart::Text { text: text.into() }],
            timestamp: now_secs(),
            metadata: None,
        }
    }

    /// Create a system message (persona / safety preamble).
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: vec![ContentPart::Text { text: text.into() }],
            timestamp: now_secs(),
            metadata: None,
        }
    }

    /// Concatenate all `Text` parts into a single string.
    /// Includes only `Text` parts.
    pub fn text_concat(&self) -> String {
        self.content
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Total character count across all text parts.
    pub fn text_len(&self) -> usize {
        self.content
            .iter()
            .map(|p| match p {
                ContentPart::Text { text } => text.len(),
                _ => 0,
            })
            .sum()
    }
}

/// Crude token estimate (≈ chars / 4 for English).
pub fn estimate_tokens(messages: &[ChatMessage]) -> usize {
    let chars: usize = messages.iter().map(|m| m.text_len()).sum();
    chars / 4
}

fn now_secs() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(error) => {
                let before_epoch = i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX);
                before_epoch.saturating_neg()
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        // On wasm32 (the Leptos web client) there is no `SystemTime`. Client-side
        // timestamps are provisional anyway: the daemon stamps the authoritative
        // ingest time when the event is written to the state stream, so
        // returning 0 here is a deliberate "unset, daemon will fill" sentinel.
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn chat_message_roundtrip() -> anyhow::Result<()> {
        let msg = ChatMessage::user("chat_platform", "C42", "hello world");
        let json = serde_json::to_string(&msg)?;
        let back: ChatMessage = serde_json::from_str(&json)?;
        ensure!(
            back.role == MessageRole::User,
            "unexpected role: {:?}",
            back.role
        );
        ensure!(
            back.text_concat() == "hello world",
            "unexpected text: {}",
            back.text_concat()
        );
        let meta = back.metadata.context("metadata missing")?;
        ensure!(
            meta.platform == "chat_platform",
            "unexpected platform: {}",
            meta.platform
        );
        ensure!(
            meta.conversation_id.as_deref() == Some("C42"),
            "unexpected conversation id: {:?}",
            meta.conversation_id
        );
        Ok(())
    }

    #[test]
    fn assistant_message_has_no_metadata() {
        let msg = ChatMessage::assistant("ok");
        assert!(msg.metadata.is_none());
    }

    #[test]
    fn text_len_counts_all_text_parts() {
        let msg = ChatMessage {
            role: MessageRole::User,
            content: vec![
                ContentPart::Text { text: "abc".into() },
                ContentPart::Text { text: "de".into() },
            ],
            timestamp: 0,
            metadata: None,
        };
        assert_eq!(msg.text_len(), 5);
    }

    #[test]
    fn estimate_tokens_approximate() {
        let msgs = vec![
            ChatMessage::user("chat_platform", "c1", "hello world"), // 11 chars
            ChatMessage::assistant("hi there"),                      // 8 chars
        ];
        let tokens = estimate_tokens(&msgs);
        // 19 chars / 4 ≈ 4
        assert!((3..=6).contains(&tokens));
    }

    #[test]
    fn content_part_serde() -> anyhow::Result<()> {
        let part = ContentPart::ToolCall {
            id: "call_1".into(),
            name: "fetch".into(),
            arguments: crate::Value::Map({
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "url".into(),
                    crate::Value::Str("https://example.invalid".into()),
                );
                m
            }),
        };
        let json = serde_json::to_string(&part)?;
        ensure!(
            json.contains("tool_call"),
            "tool_call marker missing from json"
        );
        ensure!(json.contains("call_1"), "call id missing from json");
        let back: ContentPart = serde_json::from_str(&json)?;
        ensure!(back == part, "serde roundtrip changed content part");
        Ok(())
    }

    #[test]
    fn system_message_timestamp_is_set() {
        let msg = ChatMessage::system("be helpful");
        assert!(msg.timestamp > 0 || cfg!(target_arch = "wasm32"));
    }
}
