use crate::{StateResult, TaintedValue};
use core::future::Future;
use xolotl_types::{Path, Value};

/// Point reads independent of mutation, history, or subscription support.
pub trait StateRead {
    /// Backend-owned request state; immediate backends can return `Ready`.
    type Read<'a>: Future<Output = StateResult<Option<TaintedValue>>>
    where
        Self: 'a;

    /// Read a value with its provenance from one consistent backend view.
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a>;
}

/// Explicit value-only projection of a point read.
pub trait StateReadExt: StateRead {
    /// Discard provenance for trusted host metadata.
    fn read<'a>(&'a self, path: &'a Path) -> impl Future<Output = StateResult<Option<Value>>> + 'a {
        async move { Ok(self.read_tainted(path).await?.map(|value| value.value)) }
    }
}
impl<T: StateRead + ?Sized> StateReadExt for T {}
