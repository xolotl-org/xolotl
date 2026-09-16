//! First-format program identities, independent of resident allocation layout.
//!
//! Every field has a fixed width or a length prefix. Value leaves contribute
//! their semantic digest; storage node numbers never enter program identity.

use crate::{OperationTemplate, StepRef, WaitSpec};
use xolotl_types::Value;

mod native;
mod portable;
#[cfg(test)]
mod tests;

pub(crate) use native::graph;
pub(crate) use portable::image;

struct Fingerprint(blake3::Hasher);

impl Fingerprint {
    fn new(domain: &[u8]) -> Self {
        let mut this = Self(blake3::Hasher::new());
        this.bytes(domain);
        this
    }

    fn tag(&mut self, tag: u8) {
        self.0.update(&[tag]);
    }

    fn integer(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.integer(bytes.len() as u64);
        self.0.update(bytes);
    }

    fn value(&mut self, value: &Value) {
        self.0.update(&value.semantic_digest());
    }

    fn optional_value(&mut self, value: Option<&Value>) {
        self.tag(u8::from(value.is_some()));
        if let Some(value) = value {
            self.value(value);
        }
    }

    fn optional_index(&mut self, index: Option<u32>) {
        self.tag(u8::from(index.is_some()));
        if let Some(index) = index {
            self.integer(u64::from(index));
        }
    }

    // Restricted to flat metadata which cannot contain a Value. The explicit
    // enclosing tags and length prefix separate this from the value grammar.
    fn metadata(&mut self, value: &impl serde::Serialize) -> Result<(), serde_json::Error> {
        self.bytes(&serde_json::to_vec(value)?);
        Ok(())
    }

    fn operation(&mut self, operation: &OperationTemplate) -> Result<(), serde_json::Error> {
        self.metadata(&operation.target)?;
        self.bytes(operation.method.as_bytes());
        self.metadata(&operation.method_id)?;
        self.metadata(&operation.output)?;
        self.optional_value(operation.literal_input.as_ref());
        Ok(())
    }

    fn step(&mut self, step: &StepRef) {
        self.bytes(step.name.as_bytes());
        self.optional_value(step.arg.as_ref());
    }

    fn wait(&mut self, wait: &WaitSpec) -> Result<(), serde_json::Error> {
        self.metadata(wait)
    }

    fn finish(self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}
