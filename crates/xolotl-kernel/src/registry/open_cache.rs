//! Bounded compile products. Eviction never invalidates an installed handle.

use super::{CompiledOpenPlan, OpenCacheKey};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use xolotl_types::EndpointId;

pub(super) struct CachedOpenPlan {
    plan: CompiledOpenPlan,
}

pub(super) type RetiredOpenPlans = HashMap<Arc<OpenCacheKey>, CachedOpenPlan>;

pub(super) struct OpenPlanCache {
    plans: RetiredOpenPlans,
    order: VecDeque<Arc<OpenCacheKey>>,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
}

impl Default for OpenPlanCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl OpenPlanCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            plans: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            hits: 0,
            misses: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.plans.len()
    }

    pub fn get(&mut self, key: &OpenCacheKey) -> Option<CompiledOpenPlan> {
        let plan = self.plans.get(key).map(|saved| saved.plan.clone());
        if plan.is_some() {
            self.hits = self.hits.saturating_add(1);
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        plan
    }

    /// The caller drops the replaced or evicted policy outside the registry lock.
    pub fn insert(&mut self, key: OpenCacheKey, plan: CompiledOpenPlan) -> Option<CachedOpenPlan> {
        let saved = CachedOpenPlan { plan };
        if self.capacity == 0 {
            return Some(saved);
        }
        if let Some(existing) = self.plans.get_mut(&key) {
            return Some(std::mem::replace(existing, saved));
        }
        let retired = if self.plans.len() == self.capacity {
            self.order
                .pop_front()
                .and_then(|oldest| self.plans.remove(oldest.as_ref()))
        } else {
            None
        };
        let key = Arc::new(key);
        self.order.push_back(key.clone());
        self.plans.insert(key, saved);
        retired
    }

    /// Move native captures out for destruction after releasing the registry lock.
    pub fn clear(&mut self) -> RetiredOpenPlans {
        self.order.clear();
        std::mem::take(&mut self.plans)
    }

    /// Retire only plans that captured this transport. Keep their native
    /// captures owned by the caller until after the registry lock is released.
    pub fn remove_endpoint(&mut self, id: EndpointId) -> RetiredOpenPlans {
        let mut retained = VecDeque::with_capacity(self.order.len());
        let mut retired = HashMap::new();
        while let Some(key) = self.order.pop_front() {
            let uses_endpoint = self
                .plans
                .get(key.as_ref())
                .is_some_and(|saved| saved.plan.driver_plan.endpoint == Some(id));
            if uses_endpoint {
                if let Some(plan) = self.plans.remove(key.as_ref()) {
                    retired.insert(key, plan);
                }
            } else {
                retained.push_back(key);
            }
        }
        self.order = retained;
        retired
    }
}
