#![forbid(unsafe_code)]

//! gRPC types for Andrias external clients.
//!
//! The `.proto` files under `proto/` are the schema spec. The Rust bindings are
//! hand-vendored in `src/{common,program,external}.rs` so the crate builds without
//! `protoc`.
//! If you change a `.proto`, mirror the change in the matching `.rs` module.

pub mod andrias {
    pub mod v1 {
        include!("common.rs");
        include!("program.rs");

        pub mod external {
            include!("external.rs");
        }
    }
}

pub mod convert;
pub use convert::{
    ConvertError, capability_from_pb, capability_to_pb, command_result_from_pb,
    command_result_to_pb, control_frame_from_pb, control_frame_to_pb, do_node_from_pb,
    do_node_to_pb, event_ack_from_pb, event_ack_to_pb, failure_from_pb, failure_kind,
    failure_to_pb, inbound_event_from_pb, inbound_event_to_pb, invoke_from_pb,
    invoke_result_from_pb, invoke_result_to_pb, invoke_to_pb, outbound_command_from_pb,
    outbound_command_to_pb, outcome_to_pb, output_mode_from_pb, output_mode_to_pb, path_from_pb,
    path_to_pb, program_from_pb, program_to_pb, role_ready_from_pb, role_ready_to_pb,
    role_session_client_hello_from_pb, role_session_client_hello_to_pb, session_context_from_pb,
    session_context_to_pb, value_from_pb, value_from_pb_checked, value_to_pb,
};

#[cfg(test)]
mod convert_tests;
