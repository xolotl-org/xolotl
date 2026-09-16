//! Owned leaf buffers that preserve supplied allocations.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt, ops::Deref};

/// Independently owned bytes, sharing their original immutable allocation.
///
/// Moving a Vec into this owner retains its data allocation. Supplying an
/// existing Arc slice retains that Arc instead. Cloning either form is O(1).
#[derive(Clone)]
pub struct ValueBytes(BytesStorage);

#[derive(Clone)]
enum BytesStorage {
    Owned(Arc<Vec<u8>>),
    Shared(Arc<[u8]>),
}

impl ValueBytes {
    pub(super) fn owned(bytes: Vec<u8>) -> Self {
        Self(BytesStorage::Owned(Arc::new(bytes)))
    }
    pub(super) fn shared(bytes: Arc<[u8]>) -> Self {
        Self(BytesStorage::Shared(bytes))
    }

    /// Borrow the complete byte buffer.
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            BytesStorage::Owned(bytes) => bytes,
            BytesStorage::Shared(bytes) => bytes,
        }
    }
}

impl Deref for ValueBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl From<Vec<u8>> for ValueBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::owned(bytes)
    }
}
impl From<Arc<[u8]>> for ValueBytes {
    fn from(bytes: Arc<[u8]>) -> Self {
        Self::shared(bytes)
    }
}
impl AsRef<[u8]> for ValueBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl fmt::Debug for ValueBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueBytes")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Independently owned UTF-8 text, sharing its original immutable allocation.
#[derive(Clone)]
pub struct ValueText(TextStorage);

#[derive(Clone)]
enum TextStorage {
    Owned(Arc<String>),
    Shared(Arc<str>),
}

impl ValueText {
    pub(super) fn owned(text: String) -> Self {
        Self(TextStorage::Owned(Arc::new(text)))
    }
    pub(super) fn shared(text: Arc<str>) -> Self {
        Self(TextStorage::Shared(text))
    }

    /// Borrow the complete text.
    pub fn as_str(&self) -> &str {
        match &self.0 {
            TextStorage::Owned(text) => text,
            TextStorage::Shared(text) => text,
        }
    }
}

impl Deref for ValueText {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}
impl From<String> for ValueText {
    fn from(text: String) -> Self {
        Self::owned(text)
    }
}
impl From<&str> for ValueText {
    fn from(text: &str) -> Self {
        Self::shared(text.into())
    }
}
impl From<Arc<str>> for ValueText {
    fn from(text: Arc<str>) -> Self {
        Self::shared(text)
    }
}
impl AsRef<str> for ValueText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for ValueText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueText")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;
    use anyhow::{Context, ensure};

    #[test]
    fn moved_buffers_and_extracted_owners_keep_the_original_allocation() -> anyhow::Result<()> {
        let bytes = vec![42; 65536];
        let bytes_pointer = bytes.as_ptr();
        let value = Value::bytes(bytes);
        ensure!(value.as_bytes().context("byte value")?.as_ptr() == bytes_pointer);
        let owner = value.clone().into_bytes().context("byte owner")?;
        drop(value);
        ensure!(owner.as_ptr() == bytes_pointer);
        ensure!(owner.len() == 65536);

        let text = "共享文本".repeat(8192);
        let text_pointer = text.as_ptr();
        let value = Value::string(text);
        ensure!(value.as_str().context("text value")?.as_ptr() == text_pointer);
        let owner = value.clone().into_text().context("text owner")?;
        drop(value);
        ensure!(owner.as_ptr() == text_pointer);
        ensure!(owner.chars().count() == 32768);
        Ok(())
    }

    #[test]
    fn supplied_shared_buffers_and_selected_leaves_have_independent_ownership() -> anyhow::Result<()>
    {
        let bytes: Arc<[u8]> = Arc::from([1, 2, 3]);
        let text: Arc<str> = Arc::from("leaf");
        let unrelated: Arc<[u8]> = Arc::from(vec![7; 1024 * 1024]);
        let unrelated_weak = Arc::downgrade(&unrelated);
        let parent = Value::list(vec![
            Value::shared_bytes(bytes.clone()),
            Value::shared_text(text.clone()),
            Value::shared_bytes(unrelated),
        ]);
        let leaves = parent.as_list().context("parent list")?;
        let selected = leaves.get(0).context("selected leaf")?.clone();
        ensure!(
            leaves
                .get(1)
                .and_then(Value::as_str)
                .context("text leaf")?
                .as_ptr()
                == text.as_ptr()
        );
        drop(parent);
        ensure!(unrelated_weak.upgrade().is_none());
        ensure!(selected.as_bytes().context("bytes leaf")?.as_ptr() == bytes.as_ptr());
        ensure!(Arc::strong_count(&bytes) == 2);
        ensure!(Arc::strong_count(&text) == 1);
        Ok(())
    }
}
