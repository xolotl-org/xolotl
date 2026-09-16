#![forbid(unsafe_code)]

//! Standard in-process implementations for Xolotl.
//!
//! Provider projections in this crate install local
//! [`Driver`](xolotl_kernel::Driver) implementations behind `effect://...`
//! Resources.
//!
//! Method dispatch convention: each driver's methods are listed in a
//! `*_METHODS` table in registration order; the method's index in that table
//! is its `MethodId`, which the driver matches on.

#[cfg(feature = "standard-core")]
mod approval;
#[cfg(feature = "standard-core")]
mod blob;
#[cfg(feature = "standard-core")]
mod compress;
#[cfg(feature = "standard-core")]
mod context;
#[cfg(feature = "standard-core")]
mod deliberation;
#[cfg(feature = "standard-core")]
mod error;
#[cfg(feature = "standard-core")]
mod events;
#[cfg(feature = "standard-core")]
mod fact;
#[cfg(feature = "fetch")]
mod fetch;
#[cfg(feature = "fs")]
mod fs;
#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
mod http_inference;
#[cfg(feature = "standard-core")]
mod index;
#[cfg(feature = "standard-core")]
mod inference;
#[cfg(any(
    feature = "standard-core",
    feature = "fs",
    feature = "proc",
    feature = "terminal"
))]
mod input;
#[cfg(feature = "standard-core")]
mod inspect;
#[cfg(feature = "standard-core")]
mod install;
#[cfg(feature = "standard-core")]
mod lock;
#[cfg(feature = "standard-core")]
mod memory;
#[cfg(feature = "standard-core")]
mod object;
#[cfg(feature = "standard-core")]
mod pairing;
#[cfg(feature = "proc")]
mod proc;
#[cfg(feature = "standard-core")]
mod rank;
#[cfg(feature = "standard-core")]
mod retrieval;
#[cfg(feature = "standard-core")]
mod router;
#[cfg(feature = "standard-core")]
mod state;
#[cfg(feature = "standard-core")]
mod tensor;
#[cfg(feature = "terminal")]
mod terminal;
#[cfg(feature = "standard-core")]
mod time;
#[cfg(feature = "value-objects")]
mod value_objects;

#[cfg(feature = "standard-core")]
pub use inference::{
    EchoBackend, InferenceBackend, InferenceMethodSupport, InferenceStream, ModelCapabilities,
};
#[cfg(feature = "standard-core")]
pub use install::{
    IN_PROCESS_PROJECTION_CONFIG_PREFIX, InProcessProjectionInstallEntry,
    InProcessProjectionInstallReport, InProcessProjectionInstalled, InstallError, StandardConfig,
    StandardModule, StandardModules, install_declared_in_process_projections,
    install_in_process_projection_value, install_standard,
};
#[cfg(feature = "standard-core")]
pub use pairing::PairingDisplayEdge;

#[cfg(feature = "standard-core")]
pub use retrieval::{Embedding, EmbeddingRepresentation, RetrievalConfig};

#[cfg(feature = "value-objects")]
pub use value_objects::{
    InstalledValueObjects, ValueObjectConfig, install_value_objects, memory_key_factory,
};
