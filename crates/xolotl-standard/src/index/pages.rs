//! A small persistent vector for index metadata and shared entry handles.
//!
//! Snapshots clone one root. Mutation copies at most one path of 32-way pages;
//! neither the complete directory nor an entry's numeric payload is copied.

use std::sync::Arc;

const WIDTH: usize = 32;
const BITS: u32 = 5;

#[derive(Clone)]
enum Node<T> {
    Leaf(Vec<T>),
    Branch(Vec<Arc<Node<T>>>),
}

#[derive(Clone)]
pub(super) struct Pages<T> {
    root: Option<Arc<Node<T>>>,
    len: usize,
    level: u32,
}

impl<T> Default for Pages<T> {
    fn default() -> Self {
        Self {
            root: None,
            len: 0,
            level: 0,
        }
    }
}

impl<T> Pages<T> {
    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        let mut node = self.root.as_deref()?;
        let mut level = self.level;
        loop {
            match node {
                Node::Leaf(items) => return items.get(index % WIDTH),
                Node::Branch(children) => {
                    node = children.get(branch(index, level))?.as_ref();
                    level = level.checked_sub(1)?;
                }
            }
        }
    }

    pub(super) fn iter(&self) -> Iter<'_, T> {
        Iter {
            pages: self,
            next: 0,
        }
    }
}

impl<T: Clone> Pages<T> {
    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        let mut node = self.root.as_mut()?;
        let mut level = self.level;
        loop {
            match Arc::make_mut(node) {
                Node::Leaf(items) => return items.get_mut(index % WIDTH),
                Node::Branch(children) => {
                    node = children.get_mut(branch(index, level))?;
                    level = level.checked_sub(1)?;
                }
            }
        }
    }

    pub(super) fn push(&mut self, value: T) {
        let Some(root) = &mut self.root else {
            self.root = Some(Arc::new(Node::Leaf(vec![value])));
            self.len = 1;
            return;
        };
        let root_full = ((self.len as u128) >> ((self.level + 1) * BITS)) != 0;
        if root_full {
            let next = path(self.level, value);
            self.root = Some(Arc::new(Node::Branch(vec![root.clone(), next])));
            self.level += 1;
        } else {
            append(root, self.level, self.len, value);
        }
        self.len += 1;
    }

    pub(super) fn pop(&mut self) -> Option<T> {
        let next_len = self.len.checked_sub(1)?;
        let value = remove_last(self.root.as_mut()?, self.level, next_len)?;
        self.len = next_len;
        if self.len == 0 {
            self.root = None;
            self.level = 0;
        } else if self.level != 0
            && let Some(Node::Branch(children)) = self.root.as_deref()
            && children.len() == 1
        {
            self.root = children.first().cloned();
            self.level -= 1;
        }
        Some(value)
    }

    pub(super) fn swap_remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        let tail = self.pop()?;
        if index == self.len {
            return Some(tail);
        }
        self.get_mut(index)
            .map(|item| std::mem::replace(item, tail))
    }
}

fn branch(index: usize, level: u32) -> usize {
    index.checked_shr(level * BITS).unwrap_or(0) % WIDTH
}

fn path<T>(level: u32, value: T) -> Arc<Node<T>> {
    let mut node = Arc::new(Node::Leaf(vec![value]));
    for _ in 0..level {
        node = Arc::new(Node::Branch(vec![node]));
    }
    node
}

fn append<T: Clone>(node: &mut Arc<Node<T>>, level: u32, index: usize, value: T) {
    match Arc::make_mut(node) {
        Node::Leaf(items) => items.push(value),
        Node::Branch(children) => {
            let child = branch(index, level);
            if let Some(node) = children.get_mut(child) {
                append(node, level - 1, index, value);
            } else {
                children.push(path(level - 1, value));
            }
        }
    }
}

fn remove_last<T: Clone>(node: &mut Arc<Node<T>>, level: u32, index: usize) -> Option<T> {
    match Arc::make_mut(node) {
        Node::Leaf(items) => items.pop(),
        Node::Branch(children) => {
            let child = children.last_mut()?;
            let value = remove_last(child, level - 1, index)?;
            if index.checked_shr(level * BITS).unwrap_or(0) * WIDTH.pow(level) == index {
                drop(children.pop());
            }
            Some(value)
        }
    }
}

pub(super) struct Iter<'a, T> {
    pages: &'a Pages<T>,
    next: usize,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.pages.get(self.next)?;
        self.next += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.pages.len - self.next;
        (remaining, Some(remaining))
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn snapshots_survive_changes_at_every_page_boundary() -> anyhow::Result<()> {
        let mut pages = Pages::default();
        let mut expected = Vec::new();
        for value in 0..33_001 {
            pages.push(value);
            expected.push(value);
        }
        let snapshot = pages.clone();
        let root = snapshot.root.as_ref().context("snapshot root")?;
        ensure!(Arc::ptr_eq(root, pages.root.as_ref().context("live root")?));
        for index in [0, 31, 32, 1023, 1024, 32767, 32768, 33000] {
            *pages.get_mut(index).context("page item")? += 1;
            expected[index] += 1;
        }
        ensure!(pages.iter().copied().eq(expected.iter().copied()));
        ensure!(snapshot.iter().copied().eq(0..33_001));
        while !expected.is_empty() {
            let index = expected.len() / 3;
            ensure!(pages.swap_remove(index) == Some(expected.swap_remove(index)));
        }
        ensure!(pages.root.is_none() && pages.level == 0);
        ensure!(snapshot.iter().copied().eq(0..33_001));
        Ok(())
    }
}
