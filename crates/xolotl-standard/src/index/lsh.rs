//! Optional cosine acceleration sharing the same immutable slot generation.

use super::pages::Pages;
use super::storage::Entry;
use crate::retrieval::admission::Work;
use std::collections::HashSet;
use std::sync::Arc;

pub(super) const TABLES: usize = 16;
const BITS: usize = 6;
const BUCKETS: usize = 1 << BITS;
pub(super) const CANDIDATE_FLOOR: usize = 128;
pub(super) const CANDIDATE_MULTIPLIER: usize = 32;
pub(super) type Signatures = [u8; TABLES];
type Hyperplanes = Vec<[[f32; BITS]; TABLES]>;
type Table = [Pages<usize>; BUCKETS];

#[derive(Clone, Copy)]
struct Membership {
    signatures: Signatures,
    positions: [usize; TABLES],
}

#[derive(Clone)]
pub(super) struct LshIndex {
    hyperplanes: Arc<Hyperplanes>,
    memberships: Pages<Membership>,
    // Table count and directory width are fixed by this optional algorithm;
    // membership lists themselves have no total-size limit.
    buckets: [Arc<Table>; TABLES],
}

impl LshIndex {
    #[cfg(test)]
    pub(super) fn validate(&self, entries: &Pages<Arc<Entry>>) -> Result<(), &'static str> {
        if self.memberships.len() != entries.len() {
            return Err("ANN membership count");
        }
        for (slot, membership) in self.memberships.iter().enumerate() {
            for table in 0..TABLES {
                if self.buckets[table][usize::from(membership.signatures[table])]
                    .get(membership.positions[table])
                    != Some(&slot)
                {
                    return Err("ANN reverse position");
                }
            }
        }
        for (table, buckets) in self.buckets.iter().enumerate() {
            let mut count = 0;
            for (signature, bucket) in buckets.iter().enumerate() {
                for (position, slot) in bucket.iter().enumerate() {
                    let membership = self.memberships.get(*slot).ok_or("ANN dangling slot")?;
                    if usize::from(membership.signatures[table]) != signature
                        || membership.positions[table] != position
                    {
                        return Err("ANN forward position");
                    }
                    count += 1;
                }
            }
            if count != entries.len() {
                return Err("ANN table membership count");
            }
        }
        Ok(())
    }

    pub(super) async fn build(
        entries: &Pages<Arc<Entry>>,
        dimensions: usize,
        work: &mut Work,
    ) -> Self {
        let mut hyperplanes = Vec::new();
        for dimension in 0..dimensions {
            let mut planes = [[0.0; BITS]; TABLES];
            for (table, row) in planes.iter_mut().enumerate() {
                for (bit, component) in row.iter_mut().enumerate() {
                    *component = hyperplane_component(table, bit, dimension);
                    work.tick().await;
                }
            }
            hyperplanes.push(planes);
        }
        let mut index = Self {
            hyperplanes: Arc::new(hyperplanes),
            memberships: Pages::default(),
            buckets: std::array::from_fn(|_| Arc::new(std::array::from_fn(|_| Pages::default()))),
        };
        for entry in entries.iter() {
            if let Some(vector) = entry.vector.dense() {
                let signatures = index.signature(vector, work).await;
                index.push(signatures);
            }
        }
        index
    }

    pub(super) async fn signature(&self, vector: &[f32], work: &mut Work) -> Signatures {
        let mut dots = [[0.0_f64; BITS]; TABLES];
        for (value, planes) in vector.iter().zip(self.hyperplanes.iter()) {
            for (dots, planes) in dots.iter_mut().zip(planes) {
                for (dot, plane) in dots.iter_mut().zip(planes) {
                    *dot += f64::from(*value) * f64::from(*plane);
                    work.tick().await;
                }
            }
        }
        std::array::from_fn(|table| {
            dots[table]
                .iter()
                .enumerate()
                .fold(0, |signature, (bit, dot)| {
                    signature | if *dot >= 0.0 { 1 << bit } else { 0 }
                })
        })
    }

    pub(super) fn push(&mut self, signatures: Signatures) {
        let positions = self.add_to_buckets(self.memberships.len(), signatures);
        self.memberships.push(Membership {
            signatures,
            positions,
        });
    }

    pub(super) fn replace(
        &mut self,
        slot: usize,
        signatures: Signatures,
    ) -> Result<(), &'static str> {
        let previous = self.memberships.get(slot).ok_or("missing ANN membership")?;
        if previous.signatures == signatures {
            return Ok(());
        }
        self.remove_from_buckets(slot)?;
        let positions = self.add_to_buckets(slot, signatures);
        *self
            .memberships
            .get_mut(slot)
            .ok_or("missing ANN replacement")? = Membership {
            signatures,
            positions,
        };
        Ok(())
    }

    pub(super) fn swap_remove(&mut self, slot: usize) -> Result<(), &'static str> {
        self.remove_from_buckets(slot)?;
        self.memberships
            .swap_remove(slot)
            .ok_or("missing ANN removal")?;
        if let Some(membership) = self.memberships.get(slot) {
            for (table, signature) in membership.signatures.iter().enumerate() {
                let bucket = &mut Arc::make_mut(&mut self.buckets[table])[usize::from(*signature)];
                *bucket
                    .get_mut(membership.positions[table])
                    .ok_or("missing ANN moved slot")? = slot;
            }
        }
        Ok(())
    }

    fn add_to_buckets(&mut self, slot: usize, signatures: Signatures) -> [usize; TABLES] {
        std::array::from_fn(|table| {
            let bucket =
                &mut Arc::make_mut(&mut self.buckets[table])[usize::from(signatures[table])];
            let position = bucket.len();
            bucket.push(slot);
            position
        })
    }

    fn remove_from_buckets(&mut self, slot: usize) -> Result<(), &'static str> {
        let membership = *self
            .memberships
            .get(slot)
            .ok_or("missing ANN unlink membership")?;
        for (table, signature) in membership.signatures.into_iter().enumerate() {
            let bucket = &mut Arc::make_mut(&mut self.buckets[table])[usize::from(signature)];
            let position = membership.positions[table];
            let removed = bucket
                .swap_remove(position)
                .ok_or("missing ANN bucket position")?;
            if removed != slot {
                return Err("ANN bucket position disagrees with entry");
            }
            if let Some(&moved) = bucket.get(position) {
                self.memberships
                    .get_mut(moved)
                    .ok_or("missing ANN bucket tail")?
                    .positions[table] = position;
            }
        }
        Ok(())
    }

    pub(super) async fn candidates(&self, query: &[f32], k: usize, work: &mut Work) -> Vec<usize> {
        let len = self.memberships.len();
        let budget = len.min(k.saturating_mul(CANDIDATE_MULTIPLIER).max(CANDIDATE_FLOOR));
        let mut slots = Vec::new();
        let mut seen = HashSet::new();
        for (table, signature) in self.signature(query, work).await.into_iter().enumerate() {
            for &slot in self.buckets[table][usize::from(signature)].iter() {
                work.tick().await;
                if seen.insert(slot) {
                    slots.push(slot);
                    if slots.len() == budget {
                        return slots;
                    }
                }
            }
        }
        if len == 0 || slots.len() >= budget {
            return slots;
        }
        let mut hasher = blake3::Hasher::new();
        for value in query {
            hasher.update(&value.to_bits().to_le_bytes());
            work.tick().await;
        }
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let seed = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let mut slot = (seed % len as u64) as usize;
        let step = coprime_step((seed >> 32) as usize % len, len, work).await;
        let attempts = len.min(budget.saturating_mul(8).max(CANDIDATE_FLOOR));
        for _ in 0..attempts {
            work.tick().await;
            if seen.insert(slot) {
                slots.push(slot);
                if slots.len() == budget {
                    break;
                }
            }
            slot = if slot >= len - step {
                slot - (len - step)
            } else {
                slot + step
            };
        }
        slots
    }
}

async fn coprime_step(mut step: usize, len: usize, work: &mut Work) -> usize {
    step = step.max(1);
    loop {
        let (mut a, mut b) = (step, len);
        while b != 0 {
            (a, b) = (b, a % b);
            work.tick().await;
        }
        if a == 1 {
            return step;
        }
        step = if step >= len - 1 { 1 } else { step + 1 };
        work.tick().await;
    }
}

fn hyperplane_component(table: usize, bit: usize, dimension: usize) -> f32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(table as u64).to_le_bytes());
    hasher.update(&(bit as u64).to_le_bytes());
    hasher.update(&(dimension as u64).to_le_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    (value as f32 / u32::MAX as f32) * 2.0 - 1.0
}
