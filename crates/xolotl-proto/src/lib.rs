#![forbid(unsafe_code)]

//! Version-one protobuf messages and runtime conversions for Xolotl clients.
//!
//! The default build supplies messages and conversions without a transport or
//! async runtime. `grpc` adds tonic client/server bindings over a supplied
//! service. `transport` also enables tonic's built-in channels and the clients'
//! `connect` constructors. Hosts select server routing and TLS in their tonic
//! dependency; protocol consumers do not install listeners or connections.
//!
//! The `.proto` files under `proto/` are the schema spec. The Rust bindings are
//! hand-vendored in `src/{common,program,external,console,application,federation}.rs` so the crate
//! builds without `protoc`.
//! If you change a `.proto`, mirror the change in the matching `.rs` module.

/// Namespace corresponding to the Xolotl protobuf package hierarchy.
pub mod xolotl {
    /// Version-one common values, native programs, and transport protocols.
    pub mod v1 {
        include!("common.rs");
        include!("program.rs");

        /// External role sessions, provider invocations, inbound events, and command transport.
        pub mod external {
            include!("external.rs");
        }

        /// Console sessions, subscriptions, management commands, and their response frames.
        pub mod console {
            include!("console.rs");
        }

        /// Authenticated application discovery, object upload, and surface submission.
        pub mod application {
            include!("application.rs");
        }

        /// Authenticated peer sessions and durable event exchange. The wire
        /// contract, field constraints and tag assignments are defined in
        /// `proto/xolotl/v1/federation.proto`; these vendored prost bindings
        /// mirror that schema and carry no independent authorization semantics.
        #[expect(
            missing_docs,
            reason = "wire fields are specified in the canonical federation.proto schema"
        )]
        pub mod federation {
            include!("federation.rs");
        }
    }
}

pub mod convert;
pub mod encode;
pub use convert::{
    ConvertError, MAX_WIRE_DO_DEPTH, capability_from_pb, capability_to_pb, command_result_from_pb,
    command_result_to_pb, control_frame_from_pb, control_frame_to_pb, do_node_from_pb,
    do_node_to_pb, dtype_from_str, event_ack_from_pb, event_ack_to_pb, failure_from_pb,
    failure_kind, failure_to_pb, frame_kind_from_str, inbound_event_from_pb, inbound_event_to_pb,
    invoke_from_pb, invoke_result_from_pb, invoke_result_to_pb, invoke_to_pb,
    outbound_command_from_pb, outbound_command_to_pb, outcome_to_pb, output_mode_from_pb,
    output_mode_to_pb, path_from_pb, path_to_pb, portable_program_from_pb, portable_program_to_pb,
    program_from_pb, program_to_pb, role_ready_from_pb, role_ready_to_pb,
    role_session_client_hello_from_pb, role_session_client_hello_to_pb, session_context_from_pb,
    session_context_to_pb, source_stream_request_from_pb, source_stream_request_to_pb,
    source_stream_result_from_pb, source_stream_result_to_pb, value_from_pb, value_to_pb,
};
pub use encode::{
    FailureEncodeError, MAX_VALUE_ENCODE_DEPTH, ValueEncodeError, ValueEncodeLimits,
    failure_to_pb_bounded, value_to_pb_bounded,
};

#[cfg(test)]
mod convert_tests;
