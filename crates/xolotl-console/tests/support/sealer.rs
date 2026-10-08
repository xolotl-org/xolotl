use std::sync::{Arc, OnceLock};
use xolotl_console::CredentialSealer;

#[expect(
    clippy::unwrap_used,
    reason = "fixed integration key and identifier are valid"
)]
pub fn sealer() -> Arc<CredentialSealer> {
    static SEALER: OnceLock<Arc<CredentialSealer>> = OnceLock::new();
    SEALER
        .get_or_init(|| Arc::new(CredentialSealer::new("integration", &[0x52; 32]).unwrap()))
        .clone()
}
