//! Process-owned State addresses used by handle cleanup.

use xolotl_types::{Path, ProcessId};

pub(crate) fn state_cleanup_owner(path: &Path) -> Option<ProcessId> {
    if path.scheme() != "state"
        || path.cluster().is_some()
        || path.segments().first()?.as_str() != "process"
    {
        return None;
    }
    path.segments()
        .get(1)?
        .as_str()
        .parse()
        .ok()
        .map(ProcessId::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn only_local_numeric_process_state_has_implicit_cleanup_ownership() -> anyhow::Result<()> {
        for literal in [
            "state://",
            "state://process",
            "state://process/self/result",
            "state://process/not-an-id/result",
            "state://process/18446744073709551616/result",
            "state://other/7/result",
            "effect://process/7/result",
            "path://remote/state/process/7/result",
        ] {
            ensure!(
                state_cleanup_owner(&Path::parse(literal)?).is_none(),
                "{literal}"
            );
        }
        ensure!(
            state_cleanup_owner(&Path::parse("state://process/18446744073709551615/result")?)
                == Some(ProcessId::new(u64::MAX))
        );
        Ok(())
    }
}
