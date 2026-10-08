use xolotl_console::{ConsoleAuthConfig, ConsoleConfig};

pub fn auth() -> ConsoleAuthConfig {
    ConsoleAuthConfig {
        credential_sealer: Some(crate::sealer::sealer()),
        ..Default::default()
    }
}

pub fn console_config() -> ConsoleConfig {
    ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            xolotl_console::session_store::MemoryConsoleSessionStore::new(
                xolotl_console::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        auth: auth(),
        ..Default::default()
    }
}
