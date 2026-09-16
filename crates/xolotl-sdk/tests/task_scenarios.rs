#![cfg(feature = "host")]

//! Executable composition examples using the public SDK and admitted effects.
//! The adapters simulate a device, an external service and a local model. The
//! RAG scenario uses the installed Memory and Index implementations. These do
//! not claim hardware timing, a duplex input port, or remote cancellation on drop.

mod task_scenarios {
    mod jobs;
    mod media;
    #[cfg(feature = "standard")]
    mod rag;
    mod support;
}
