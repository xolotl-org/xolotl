//! One exhaustive index visitor shared by image and module-boundary validation.

use super::{Node, NodeKind};

impl<V, E> Node<V, E> {
    /// Visit every instruction, import and binding address without copying values.
    /// The first rejected address stops traversal. Hosts use this to validate
    /// independently relocated modules within a larger instruction arena.
    pub fn visit_indices<F>(
        &self,
        mut node: impl FnMut(u32) -> Result<(), F>,
        mut import: impl FnMut(u32) -> Result<(), F>,
        mut binding: impl FnMut(u32) -> Result<(), F>,
    ) -> Result<(), F> {
        if let Some(next) = self.next {
            node(next)?;
        }
        if let Some(save) = self.save {
            binding(save)?;
        }
        match &self.kind {
            NodeKind::Literal(_) | NodeKind::Input | NodeKind::Fail(_) => {}
            NodeKind::Load(slot) => binding(*slot)?,
            NodeKind::Request(index) => import(*index)?,
            NodeKind::Call(entry) => node(*entry)?,
            NodeKind::Then { first: a, then: b }
            | NodeKind::Catch {
                body: a,
                recover: b,
            }
            | NodeKind::Finally {
                body: a,
                cleanup: b,
            }
            | NodeKind::If { yes: a, no: b }
            | NodeKind::While {
                condition: a,
                body: b,
                ..
            }
            | NodeKind::Fork {
                left: a, right: b, ..
            } => {
                node(*a)?;
                node(*b)?;
            }
            NodeKind::Branch { condition, yes, no } => {
                node(*condition)?;
                node(*yes)?;
                node(*no)?;
            }
            NodeKind::Let { slot, value, body } => {
                binding(*slot)?;
                node(*value)?;
                node(*body)?;
            }
            NodeKind::Scope {
                import: index,
                body,
            } => {
                import(*index)?;
                node(*body)?;
            }
        }
        Ok(())
    }
}
