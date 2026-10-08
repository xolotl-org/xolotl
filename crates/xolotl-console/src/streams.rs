//! Shared admission limits for subscriptions through every Console adapter.

use crate::auth::AccountKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Limits shared by Rust callers and all network transports.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleStreamConfig {
    /// Maximum live subscriptions on this host.
    pub max_subscriptions_global: usize,
    /// Maximum live subscriptions belonging to one account instance.
    pub max_subscriptions_per_account: usize,
    /// Maximum canonical v1 protobuf event bytes, including the largest stream id.
    /// Also bounds value-conversion work for embedded callers.
    pub max_event_bytes: usize,
}

impl Default for ConsoleStreamConfig {
    fn default() -> Self {
        Self {
            max_subscriptions_global: 1024,
            max_subscriptions_per_account: 64,
            max_event_bytes: 1024 * 1024,
        }
    }
}

pub(crate) struct StreamAdmission {
    config: ConsoleStreamConfig,
    counts: Mutex<Counts>,
}

#[derive(Default)]
struct Counts {
    total: usize,
    accounts: HashMap<AccountKey, usize>,
}

impl StreamAdmission {
    pub fn new(mut config: ConsoleStreamConfig) -> Arc<Self> {
        config.max_subscriptions_global = config.max_subscriptions_global.clamp(1, 65_536);
        config.max_subscriptions_per_account = config.max_subscriptions_per_account.clamp(1, 4096);
        config.max_event_bytes = config.max_event_bytes.clamp(1024, 4 * 1024 * 1024);
        Arc::new(Self {
            config,
            counts: Mutex::new(Counts::default()),
        })
    }

    pub fn acquire(
        self: &Arc<Self>,
        account: AccountKey,
    ) -> Result<StreamLease, crate::service::ConsoleError> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if counts.total >= self.config.max_subscriptions_global
            || counts.accounts.get(&account).copied().unwrap_or_default()
                >= self.config.max_subscriptions_per_account
        {
            return Err(crate::service::ConsoleError::RateLimited);
        }
        counts.total += 1;
        *counts.accounts.entry(account.clone()).or_default() += 1;
        Ok(StreamLease {
            admission: self.clone(),
            account,
        })
    }

    pub fn config(&self) -> &ConsoleStreamConfig {
        &self.config
    }

    pub fn max_event_bytes(&self) -> usize {
        self.config.max_event_bytes
    }
}

pub(crate) struct StreamLease {
    admission: Arc<StreamAdmission>,
    account: AccountKey,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        let mut counts = self
            .admission
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        counts.total -= 1;
        if let Some(count) = counts.accounts.get_mut(&self.account) {
            *count -= 1;
            if *count == 0 {
                counts.accounts.remove(&self.account);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_account_has_its_own_subscription_budget() -> Result<(), String> {
        let admission = StreamAdmission::new(ConsoleStreamConfig {
            max_subscriptions_global: 3,
            max_subscriptions_per_account: 1,
            ..Default::default()
        });
        let old = admission
            .acquire(AccountKey::local("old-instance"))
            .map_err(|error| format!("old account lease: {error:?}"))?;
        if admission.acquire(AccountKey::local("old-instance")).is_ok() {
            return Err("old account exceeded its subscription budget".into());
        }
        let replacement = admission
            .acquire(AccountKey::local("new-instance"))
            .map_err(|error| format!("replacement account lease: {error:?}"))?;
        drop(old);
        let another_old = admission
            .acquire(AccountKey::local("old-instance"))
            .map_err(|error| format!("old account budget was not released: {error:?}"))?;
        drop(another_old);
        drop(replacement);
        Ok(())
    }
}
