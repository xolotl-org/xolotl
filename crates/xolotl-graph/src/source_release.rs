use alloc::vec::Vec;
use core::mem;

pub(crate) trait SourceTree: Sized {
    fn has_children(&self) -> bool;
    fn empty() -> Self;
    fn detach_children(&mut self, pending: &mut Vec<Self>);

    fn take_children(&mut self) -> Option<alloc::vec::IntoIter<Self>> {
        None
    }
}

pub(crate) fn detach<Node: SourceTree>(node: &mut Node, pending: &mut Vec<Node>) {
    if node.has_children() {
        pending.push(mem::replace(node, Node::empty()));
    }
}

pub(crate) fn release<Node: SourceTree>(root: &mut Node) {
    release_observed(root, |_| {});
}

fn release_observed<Node: SourceTree>(root: &mut Node, mut observe: impl FnMut(usize)) {
    let mut pending = Vec::new();
    let mut cursors = Vec::new();
    root.detach_children(&mut pending);
    if let Some(cursor) = root.take_children() {
        cursors.push(cursor);
    }
    loop {
        observe(pending.len() + cursors.len());
        let mut node = if let Some(node) = pending.pop() {
            node
        } else if let Some(mut cursor) = cursors.pop() {
            let Some(node) = cursor.next() else {
                continue;
            };
            if cursor.len() != 0 {
                cursors.push(cursor);
            }
            node
        } else {
            break;
        };
        node.detach_children(&mut pending);
        if let Some(cursor) = node.take_children() {
            cursors.push(cursor);
        }
    }
}

pub(crate) fn release_json(root: &mut serde_json::Value) {
    release_json_observed(root, |_| {});
}

enum JsonCursor {
    Array(alloc::vec::IntoIter<serde_json::Value>),
    Object(serde_json::map::IntoIter),
}

impl JsonCursor {
    fn next(&mut self) -> Option<serde_json::Value> {
        match self {
            Self::Array(children) => children.next(),
            Self::Object(children) => children.next().map(|(_, value)| value),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Array(children) => children.len(),
            Self::Object(children) => children.len(),
        }
    }
}

fn json_has_children(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(children) => !children.is_empty(),
        serde_json::Value::Object(children) => !children.is_empty(),
        _ => false,
    }
}

fn release_json_observed(root: &mut serde_json::Value, mut observe: impl FnMut(usize)) {
    let mut cursors = Vec::new();
    let mut value = mem::replace(root, serde_json::Value::Null);
    loop {
        let mut cursor = match value {
            serde_json::Value::Array(mut children) => {
                children.retain(json_has_children);
                JsonCursor::Array(children.into_iter())
            }
            serde_json::Value::Object(mut children) => {
                children.retain(|_, value| json_has_children(value));
                JsonCursor::Object(children.into_iter())
            }
            _ => break,
        };
        let next = match cursor.next() {
            Some(child) => Some(child),
            None => {
                drop(cursor);
                let Some(parent) = cursors.pop() else {
                    observe(0);
                    break;
                };
                cursor = parent;
                cursor.next()
            }
        };
        if cursor.len() != 0 {
            cursors.push(cursor);
        }
        observe(cursors.len());
        let Some(child) = next else { break };
        value = child;
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceTree, release_json_observed, release_observed};
    use crate::portable::{Expression, Program};
    use crate::{CompileError, DoNode, StepRef, compile_do, compile_do_at};
    use alloc::{boxed::Box, vec};
    use std::{
        panic::{catch_unwind, resume_unwind},
        thread,
    };
    use xolotl_types::Path;

    fn small_stack(
        test: impl FnOnce() -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<()> {
        thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(test)?
            .join()
            .map_err(|_panic| anyhow::anyhow!("small-stack worker panicked"))?
    }

    fn native_tree(depth: usize) -> anyhow::Result<DoNode> {
        let mut body = DoNode::wait_deadline(0);
        let identity = Path::parse("identity://host")?;
        for level in 0..depth {
            let (first, second) = if level / 7 % 2 == 0 {
                (body, DoNode::wait_deadline(0))
            } else {
                (DoNode::wait_deadline(0), body)
            };
            body = match level % 7 {
                0 => DoNode::both(first, second).and_then(StepRef::new("next")),
                1 => DoNode::both(first, second).or_else(StepRef::new("recover")),
                2 => DoNode::Finally {
                    body: Box::new(first),
                    cleanup: Box::new(second),
                },
                3 => DoNode::both(first, second),
                4 => DoNode::race(first, second),
                5 => DoNode::Let {
                    name: "value".into(),
                    value: Box::new(first),
                    body: Box::new(second),
                },
                _ => DoNode::Acting {
                    identity: identity.clone(),
                    body: Box::new(DoNode::both(first, second)),
                },
            };
        }
        Ok(body)
    }

    fn portable_tree(depth: usize) -> anyhow::Result<Expression> {
        let mut body = Expression::Input;
        let identity = Path::parse("identity://host")?;
        for level in 0..depth {
            let (first, second) = if level / 9 % 2 == 0 {
                (body, Expression::Input)
            } else {
                (Expression::Input, body)
            };
            body = match level % 9 {
                0 => Expression::Sequence {
                    steps: vec![first, second],
                },
                1 => Expression::Let {
                    name: "value".into(),
                    value: Box::new(first),
                    body: Box::new(second),
                },
                2 => {
                    let mut branches = [Expression::Input, Expression::Input, Expression::Input];
                    branches[level / 9 % 3] = first.then(second);
                    let [condition, yes, no] = branches;
                    Expression::If {
                        condition: Box::new(condition),
                        yes: Box::new(yes),
                        no: Box::new(no),
                    }
                }
                3 => Expression::While {
                    condition: Box::new(first),
                    body: Box::new(second),
                    max_iterations: 1,
                },
                4 => first.both(second),
                5 => first.race(second),
                6 => Expression::Catch {
                    body: Box::new(first),
                    recover: Box::new(second),
                },
                7 => first.finally(second),
                _ => Expression::Acting {
                    identity: identity.clone(),
                    body: Box::new(first.then(second)),
                },
            };
        }
        Ok(body)
    }

    fn json_tree(depth: usize, terminal_first: bool) -> serde_json::Value {
        let mut value = serde_json::Value::Null;
        for level in 0..depth {
            value = if level % 2 == 0 {
                let terminal = serde_json::Value::String("terminal payload".into());
                let children = if terminal_first {
                    vec![terminal, value]
                } else {
                    vec![value, terminal]
                };
                serde_json::Value::Array(children)
            } else {
                let mut children = serde_json::Map::new();
                let (nested, terminal) = if terminal_first {
                    ("z", "a")
                } else {
                    ("a", "z")
                };
                children.insert(nested.into(), value);
                children.insert(terminal.into(), serde_json::Value::Bool(true));
                serde_json::Value::Object(children)
            };
        }
        value
    }

    #[test]
    fn sequence_cleanup_reuses_the_owned_allocation() -> anyhow::Result<()> {
        let steps: alloc::vec::Vec<_> = (0..4096)
            .map(|_| Expression::Sequence {
                steps: vec![Expression::Input],
            })
            .collect();
        let allocation = steps.as_ptr();
        let mut source = Expression::Sequence { steps };
        let cursor = source
            .take_children()
            .ok_or_else(|| anyhow::anyhow!("missing cursor"))?;
        anyhow::ensure!(cursor.as_slice().as_ptr() == allocation);
        anyhow::ensure!(cursor.len() == 4096);
        anyhow::ensure!(!source.has_children());
        drop(cursor);
        Ok(())
    }

    #[test]
    fn terminal_sources_and_wide_terminal_sequences_need_no_ast_scratch() -> anyhow::Result<()> {
        for mut source in [
            Expression::Input,
            Expression::Literal {
                value: json_tree(128, false),
            },
            Expression::Sequence {
                steps: (0..16_384)
                    .map(|_| Expression::Fail {
                        message: "owned payload".into(),
                    })
                    .collect(),
            },
        ] {
            let mut peak = 0;
            release_observed(&mut source, |pending| peak = peak.max(pending));
            anyhow::ensure!(peak == 0);
            anyhow::ensure!(!source.has_children());
        }
        Ok(())
    }

    #[test]
    fn json_terminal_variants_are_discarded_without_pending_cursors() -> anyhow::Result<()> {
        let mut value = serde_json::Value::Array(vec![
            serde_json::Value::Null,
            serde_json::Value::Bool(true),
            serde_json::Value::Number(42.into()),
            serde_json::Value::String("owned payload".into()),
            serde_json::Value::Array(vec![]),
            serde_json::Value::Object(serde_json::Map::new()),
        ]);
        let mut peak = 0;
        release_json_observed(&mut value, |pending| peak = peak.max(pending));
        anyhow::ensure!(peak == 0);
        anyhow::ensure!(value.is_null());
        Ok(())
    }

    #[test]
    fn wide_sequence_cleanup_uses_one_cursor_not_full_node_slots() -> anyhow::Result<()> {
        let steps = (0..16_384)
            .map(|_| Expression::Sequence {
                steps: vec![Expression::Fail {
                    message: "owned terminal payload".into(),
                }],
            })
            .collect();
        let mut source = Expression::Sequence { steps };
        let mut peak = 0;
        release_observed(&mut source, |pending| peak = peak.max(pending));
        anyhow::ensure!(peak == 1);
        anyhow::ensure!(!source.has_children());
        Ok(())
    }

    #[test]
    fn deep_sequence_terminal_siblings_do_not_retain_ancestor_cursors() -> anyhow::Result<()> {
        small_stack(|| {
            for terminal_first in [false, true] {
                let mut source = Expression::Input;
                for _ in 0..10_000 {
                    let terminal = Expression::Literal {
                        value: serde_json::Value::String("owned payload".into()),
                    };
                    let steps = if terminal_first {
                        vec![terminal, source]
                    } else {
                        vec![source, terminal]
                    };
                    source = Expression::Sequence { steps };
                }
                let mut peak = 0;
                release_observed(&mut source, |pending| peak = peak.max(pending));
                anyhow::ensure!(peak == 1);
                anyhow::ensure!(!source.has_children());
            }
            Ok(())
        })
    }

    #[test]
    fn deep_json_terminal_siblings_do_not_retain_ancestor_cursors() -> anyhow::Result<()> {
        small_stack(|| {
            for terminal_first in [false, true] {
                let mut value = json_tree(10_000, terminal_first);
                let mut peak = 0;
                let mut containers = 0;
                release_json_observed(&mut value, |pending| {
                    peak = peak.max(pending);
                    containers += 1;
                });
                anyhow::ensure!(peak == 0);
                anyhow::ensure!(containers == 10_000);
                anyhow::ensure!(value.is_null());
            }
            Ok(())
        })
    }

    #[test]
    fn wide_json_cleanup_visits_every_branch_with_bounded_cursors() -> anyhow::Result<()> {
        for object in [false, true] {
            let children = (0..4096).map(|index| {
                let value = serde_json::Value::Array(vec![serde_json::Value::Array(vec![
                    serde_json::Value::String("owned payload".into()),
                ])]);
                (alloc::format!("child-{index}"), value)
            });
            let mut value = if object {
                serde_json::Value::Object(children.collect())
            } else {
                serde_json::Value::Array(children.map(|(_, value)| value).collect())
            };
            let mut peak = 0;
            let mut containers = 0;
            release_json_observed(&mut value, |pending| {
                peak = peak.max(pending);
                containers += 1;
            });
            anyhow::ensure!(peak == 1);
            anyhow::ensure!(containers == 1 + 2 * 4096);
            anyhow::ensure!(value.is_null());
        }
        Ok(())
    }

    #[test]
    fn accepted_native_source_clones_compiles_and_releases_all_branch_kinds_on_small_stack()
    -> anyhow::Result<()> {
        small_stack(|| {
            let source = native_tree(10_000)?;
            let nodes = source.size();
            let graph = compile_do(&source)?;
            anyhow::ensure!(graph.nodes.len() == nodes);
            anyhow::ensure!(graph.edges.len() == nodes - 1);
            let fragment = compile_do_at(&source, 0)?;
            anyhow::ensure!(fragment.nodes == graph.nodes);
            anyhow::ensure!(fragment.edges == graph.edges);
            anyhow::ensure!(fragment.root == graph.root);
            let cloned = source.clone();
            anyhow::ensure!(compile_do(&cloned)?.graph_hash == graph.graph_hash);
            anyhow::ensure!(matches!(
                compile_do_at(&source, u32::MAX),
                Err(CompileError::PositionExhausted)
            ));
            drop(cloned);
            drop(fragment);
            drop(graph);
            drop(source);
            Ok(())
        })
    }

    #[test]
    fn rejected_portable_source_and_function_release_on_small_stack() -> anyhow::Result<()> {
        small_stack(|| {
            let mut source = Program::new(portable_tree(10_000)?);
            source
                .functions
                .insert("helper".into(), portable_tree(10_000)?);
            anyhow::ensure!(matches!(
                source.compile(),
                Err(crate::portable::CompileError::Capacity)
            ));
            drop(source);
            Ok(())
        })
    }

    #[test]
    fn rejected_json_literal_releases_arrays_and_objects_on_small_stack() -> anyhow::Result<()> {
        small_stack(|| {
            let mut value = serde_json::Value::Null;
            for level in 0..10_000 {
                value = if level % 2 == 0 {
                    serde_json::Value::Array(vec![value])
                } else {
                    let mut object = serde_json::Map::new();
                    object.insert("child".into(), value);
                    serde_json::Value::Object(object)
                };
            }
            let source = Program::new(Expression::Literal { value });
            anyhow::ensure!(matches!(
                source.compile(),
                Err(crate::portable::CompileError::Capacity)
            ));
            drop(source);
            Ok(())
        })
    }

    #[test]
    fn source_cleanup_remains_stack_bounded_during_unwind() -> anyhow::Result<()> {
        small_stack(|| {
            let native = native_tree(10_000)?;
            let portable = portable_tree(10_000)?;
            let literal = Expression::Literal {
                value: json_tree(10_000, false),
            };
            let result = catch_unwind(move || {
                let _native = native;
                let _portable = portable;
                let _literal = literal;
                resume_unwind(Box::new("exercise source cleanup"));
            });
            anyhow::ensure!(result.is_err());
            Ok(())
        })
    }
}
