#![forbid(unsafe_code)]

//! gRPC types for Nexus — the wire schema used by cross-language clients
//! (browser extension / mobile / bridges).
//!
//! The `.proto` files under `proto/` are the schema spec. The Rust bindings are
//! **hand-vendored** in `src/{common,gateway,extension}.rs` (faithful to
//! `tonic-prost-build` 0.14 output) so the crate builds **without `protoc`**.
//! If you change a `.proto`, mirror the change in the matching `.rs` module.

#![allow(clippy::all)]
#![allow(missing_docs)]

pub mod nexus {
    pub mod v1 {
        include!("common.rs");
        include!("gateway.rs");

        pub mod extension {
            include!("extension.rs");
        }
    }
}

pub mod convert;
pub use convert::{
    capability_from_pb, capability_to_pb, do_node_from_pb, do_node_to_pb, failure_from_pb,
    failure_kind, failure_to_pb, outcome_to_pb, path_from_pb, path_to_pb, program_from_pb,
    program_to_pb, value_from_pb, value_to_pb,
};

#[cfg(test)]
mod convert_tests;
