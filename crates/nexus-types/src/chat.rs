//! Standard conversation message schema.
//!
//! All chat channels (Slack, CLI, Web, X, etc.) serialise their messages
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
    System,
    User,
    Assistant,
    Tool,
}

/// One content part inside a multi-modal message.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    ToolCall {
        id: String,
        name: String,
        arguments: crate::Value,
    },
    ToolResult {
        id: String,
        result: crate::Value,
    },
    ImageRef {
        blob: BlobRef,
    },
    /// Opaque structured data passed through to the inference backend
    /// without interpretation (e.g. provider-specific cache-control hints).
    Opaque {
        kind: String,
        payload: crate::Value,
    },
}

/// A single turn in a conversation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    pub content: Vec<ContentPart>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// Platform-specific metadata (sender id, channel, etc.).
    /// Never injected into the model prompt — only used for
    /// routing and audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ChatMetadata>,
}

/// Platform-scoped metadata attached to every message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatMetadata {
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,
    /// Opaque extra fields the platform connector wants to carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<crate::Value>,
}

impl ChatMessage {
    /// Create a simple user text message with the given platform metadata.
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
    /// Non-text parts are silently skipped.
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
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
    #[cfg(target_arch = "wasm32")]
    {
        // On wasm32 (the Leptos web client) there is no `SystemTime`. Client-side
        // timestamps are provisional anyway: the daemon stamps the authoritative
        // ingest time when the event is written to the state stream (§16.3.3), so
        // returning 0 here is a deliberate "unset, daemon will fill" sentinel.
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_message_roundtrip() {
        let msg = ChatMessage::user("slack", "C42", "hello world");
        let json = serde_json::to_string(&msg).unwrap();
        let back: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.role, MessageRole::User);
        assert_eq!(back.text_concat(), "hello world");
        let meta = back.metadata.unwrap();
        assert_eq!(meta.platform, "slack");
        assert_eq!(meta.conversation_id.as_deref(), Some("C42"));
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
            ChatMessage::user("slack", "c1", "hello world"), // 11 chars
            ChatMessage::assistant("hi there"),              // 8 chars
        ];
        let tokens = estimate_tokens(&msgs);
        // 19 chars / 4 ≈ 4
        assert!((3..=6).contains(&tokens));
    }

    #[test]
    fn content_part_serde() {
        let part = ContentPart::ToolCall {
            id: "call_1".into(),
            name: "fetch".into(),
            arguments: crate::Value::Map({
                let mut m = std::collections::BTreeMap::new();
                m.insert("url".into(), crate::Value::Str("https://ex.com".into()));
                m
            }),
        };
        let json = serde_json::to_string(&part).unwrap();
        assert!(json.contains("tool_call"));
        assert!(json.contains("call_1"));
        let back: ContentPart = serde_json::from_str(&json).unwrap();
        assert_eq!(back, part);
    }

    #[test]
    fn system_message_timestamp_is_set() {
        let msg = ChatMessage::system("be helpful");
        assert!(msg.timestamp > 0 || cfg!(target_arch = "wasm32"));
    }
}
