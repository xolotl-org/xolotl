//! Console state: the kernel handle and the management-domain identity (§18.4).
//!
//! The Web Console is a **management-domain Gateway**: it maps authenticated
//! console users to a management identity and runs their actions as ordinary
//! capability-bound Operations. There is no privileged backdoor and no bespoke
//! wire protocol — every action is a `Value.write`+Cas, an inspect read, or a
//! subscribe on a `state://kernel/*` Resource (§18.4).

use nexus_kernel::Bootstrap;
use nexus_state::Backend;
use std::sync::Arc;

use crate::auth::ConsoleAuth;

/// Shared console backend state.
pub struct ConsoleState {
    pub boot: Arc<Bootstrap>,
    /// The state backend the console reads/writes management config through.
    /// All management config lives under `state://kernel/*` (Layer 1, §12).
    pub state: Backend,
    pub auth: ConsoleAuth,
}

impl ConsoleState {
    pub fn new(boot: Arc<Bootstrap>) -> Self {
        let state = boot.kernel.state.clone();
        Self {
            boot,
            state,
            auth: ConsoleAuth::default(),
        }
    }

    pub fn shared(boot: Arc<Bootstrap>) -> Arc<Self> {
        Arc::new(Self::new(boot))
    }
}
