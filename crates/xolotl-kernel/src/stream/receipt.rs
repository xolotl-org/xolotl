//! Bounded evidence for a durably acknowledged output prefix.

use serde::{Deserialize, Serialize};
use xolotl_types::{Failure, OperationId};

/// Fixed-size evidence for the output prefix accepted before an account result
/// was committed. This binds presentation data to one logical operation; it is
/// not evidence that an external Driver effect committed. The caller must hash
/// the same stable, sequence-independent bytes it writes to its output store.
/// A decoded nonempty digest can only be checked against that store's chunks;
/// this record alone does not prove that those chunks exist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamReceipt {
    operation: OperationId,
    chunks: u64,
    prefix_digest: [u8; 32],
}

impl StreamReceipt {
    /// Start an empty prefix for one replay-stable operation identity.
    pub fn new(operation: OperationId) -> Self {
        Self {
            operation,
            chunks: 0,
            prefix_digest: Self::empty_digest(operation),
        }
    }

    /// Operation whose ordered chunks this receipt covers.
    pub fn operation(&self) -> OperationId {
        self.operation
    }

    /// Number of acknowledged chunks, excluding the operation terminal.
    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Domain-separated, length-framed digest of the acknowledged prefix.
    pub fn prefix_digest(&self) -> &[u8; 32] {
        &self.prefix_digest
    }

    /// Extend the receipt after the output store acknowledges this chunk. The
    /// bytes must be the store's canonical event payload, without its global
    /// delivery sequence. No chunk data is retained here.
    pub fn append_chunk(&mut self, encoded: &[u8]) -> Result<(), Failure> {
        let ordinal = self
            .chunks
            .checked_add(1)
            .ok_or_else(|| error("stream chunk ordinal exhausted"))?;
        let len = u64::try_from(encoded.len())
            .map_err(|_error| error("stream chunk length exhausted"))?;
        let mut hash = blake3::Hasher::new_derive_key("xolotl kernel stream prefix v1");
        hash.update(&self.prefix_digest);
        hash.update(&ordinal.to_be_bytes());
        hash.update(&len.to_be_bytes());
        hash.update(encoded);
        self.prefix_digest = *hash.finalize().as_bytes();
        self.chunks = ordinal;
        Ok(())
    }

    fn empty_digest(operation: OperationId) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("xolotl kernel stream prefix v1");
        hash.update(&operation.to_bytes());
        *hash.finalize().as_bytes()
    }

    pub(crate) fn validate(&self, operation: OperationId) -> Result<(), Failure> {
        if self.operation != operation
            || self.chunks == 0 && self.prefix_digest != Self::empty_digest(operation)
        {
            return Err(error("stream receipt identity or empty prefix is invalid"));
        }
        Ok(())
    }
}

fn error(reason: &str) -> Failure {
    Failure::policy("accounting", reason)
}
