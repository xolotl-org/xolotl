#![forbid(unsafe_code)]

//! gRPC types for Xolotl external clients.
//!
//! The `.proto` files under `proto/` are the schema spec. The Rust bindings are
//! hand-vendored in `src/{common,program,external,console,application}.rs` so the crate
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
    }
}

pub mod convert;
pub mod encode;
pub use convert::{
    ConvertError, capability_from_pb, capability_to_pb, command_result_from_pb,
    command_result_to_pb, control_frame_from_pb, control_frame_to_pb, do_node_from_pb,
    do_node_to_pb, dtype_from_str, event_ack_from_pb, event_ack_to_pb, failure_from_pb,
    failure_kind, failure_to_pb, frame_kind_from_str, inbound_event_from_pb, inbound_event_to_pb,
    invoke_from_pb, invoke_result_from_pb, invoke_result_to_pb, invoke_to_pb,
    outbound_command_from_pb, outbound_command_to_pb, outcome_to_pb, output_mode_from_pb,
    output_mode_to_pb, path_from_pb, path_to_pb, portable_program_from_pb, portable_program_to_pb,
    program_from_pb, program_to_pb, role_ready_from_pb, role_ready_to_pb,
    role_session_client_hello_from_pb, role_session_client_hello_to_pb, session_context_from_pb,
    session_context_to_pb, value_from_pb, value_from_pb_checked, value_to_pb,
};
pub use encode::{
    FailureEncodeError, MAX_VALUE_ENCODE_DEPTH, ValueEncodeError, ValueEncodeLimits,
    failure_to_pb_bounded, value_to_pb_bounded,
};

#[cfg(test)]
mod convert_tests;
