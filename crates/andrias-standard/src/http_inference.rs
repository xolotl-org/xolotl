//! HTTP inference provider backends for `effect://inference/*`.
//!
//! The API dialect is separate from the vendor. OpenAI-compatible third
//! parties use the OpenAI chat dialect with their own base URL and model id.

mod backend;
mod config;
mod dialects;
mod error;
mod request;
mod routing;
mod state;

#[cfg(test)]
mod tests;

pub(crate) use error::HttpInferenceError;
pub(crate) use state::router_from_state;
