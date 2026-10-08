use super::*;

pub(super) struct DisabledFactStore;

fn unavailable() -> FactError {
    FactError::new("observation storage is not installed".into())
}

impl FactStore for DisabledFactStore {
    fn is_enabled(&self) -> bool {
        false
    }
    fn append(&self, _fact: Fact) -> Result<u64, FactError> {
        Err(unavailable())
    }
    fn complete(&self, _fact: Fact) -> Result<(), FactError> {
        Err(unavailable())
    }
    fn scan(&self, _query: FactQuery) -> Result<FactPage, FactError> {
        Err(unavailable())
    }
    fn lookup(&self, _query: FactLookup) -> Result<FactLookupResult, FactError> {
        Err(unavailable())
    }
    fn facts_of(&self, _process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        Err(unavailable())
    }
    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        Err(unavailable())
    }
    fn cursor(&self) -> u64 {
        0
    }
    fn observed_cursor(&self) -> Result<u64, FactError> {
        Err(unavailable())
    }
}
