//! Shared streaming matrix and separately enabled dialect-specific checks.

#[cfg(feature = "openai-chat")]
mod chat;
mod incremental;
