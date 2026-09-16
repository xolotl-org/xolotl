use super::Fingerprint;
use crate::portable::{Import, Transform};
use xolotl_core::{IMAGE_VERSION, Node, NodeKind};
use xolotl_types::{Failure, Value};

pub(crate) fn image(
    nodes: &[Node<Value, Failure>],
    imports: &[Import],
    entry: u32,
    bindings: usize,
    durable: bool,
) -> Result<[u8; 32], serde_json::Error> {
    let mut digest = Fingerprint::new(b"xolotl-portable-image-v1");
    digest.integer(u64::from(IMAGE_VERSION));
    digest.integer(nodes.len() as u64);
    for node in nodes {
        digest.instruction(&node.kind)?;
        digest.optional_index(node.next);
        digest.optional_index(node.save);
        digest.integer(node.position);
    }
    digest.integer(imports.len() as u64);
    for import in imports {
        match import {
            Import::Operation(operation) => {
                digest.tag(0);
                digest.operation(operation)?;
            }
            Import::Transform(transform) => {
                digest.tag(1);
                digest.transform(transform);
            }
            Import::Wait(wait) => {
                digest.tag(2);
                digest.wait(wait)?;
            }
            Import::Scope(path) => {
                digest.tag(3);
                digest.metadata(path)?;
            }
            Import::Module(step) => {
                digest.tag(4);
                digest.step(step);
            }
        }
    }
    digest.integer(u64::from(entry));
    digest.integer(bindings as u64);
    digest.tag(u8::from(durable));
    Ok(digest.finish())
}

impl Fingerprint {
    fn transform(&mut self, transform: &Transform) {
        match transform {
            Transform::Field { name } => {
                self.tag(0);
                self.bytes(name.as_bytes());
            }
            Transform::Index { index } => {
                self.tag(1);
                self.integer(*index as u64);
            }
            Transform::Add { value } => {
                self.tag(2);
                self.0.update(&value.to_le_bytes());
            }
            Transform::LessThan { value } => {
                self.tag(3);
                self.0.update(&value.to_le_bytes());
            }
            Transform::Equal { value } => {
                self.tag(4);
                self.value(value);
            }
            Transform::Not => self.tag(5),
            Transform::Length => self.tag(6),
        }
    }

    fn instruction(&mut self, node: &NodeKind<Value, Failure>) -> Result<(), serde_json::Error> {
        match node {
            NodeKind::Literal(value) => {
                self.tag(0);
                self.value(value);
            }
            NodeKind::Input => self.tag(1),
            NodeKind::Load(slot) => {
                self.tag(2);
                self.integer(u64::from(*slot));
            }
            NodeKind::Fail(failure) => {
                self.tag(3);
                self.metadata(failure)?;
            }
            NodeKind::Request(import) => {
                self.tag(4);
                self.integer(u64::from(*import));
            }
            NodeKind::Then { first, then } => self.indices(5, &[*first, *then]),
            NodeKind::Catch { body, recover } => self.indices(6, &[*body, *recover]),
            NodeKind::Finally { body, cleanup } => self.indices(7, &[*body, *cleanup]),
            NodeKind::If { yes, no } => self.indices(8, &[*yes, *no]),
            NodeKind::Branch { condition, yes, no } => self.indices(9, &[*condition, *yes, *no]),
            NodeKind::Let { slot, value, body } => self.indices(10, &[*slot, *value, *body]),
            NodeKind::While {
                condition,
                body,
                max,
            } => {
                self.indices(11, &[*condition, *body]);
                self.integer(*max);
            }
            NodeKind::Fork { left, right, join } => {
                self.indices(12, &[*left, *right]);
                self.tag(match join {
                    xolotl_core::Join::All => 0,
                    xolotl_core::Join::Race => 1,
                });
            }
            NodeKind::Call(entry) => self.indices(13, &[*entry]),
            NodeKind::Scope { import, body } => self.indices(14, &[*import, *body]),
        }
        Ok(())
    }

    fn indices(&mut self, tag: u8, indices: &[u32]) {
        self.tag(tag);
        for index in indices {
            self.integer(u64::from(*index));
        }
    }
}
