//! Flat ordered lineage storage. Empty sets have no shared allocation.

use super::{TaintSet, TaintSource};
use alloc::{sync::Arc, vec::Vec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(super) fn serialize<S: Serializer>(
    sources: &Option<Arc<Vec<TaintSource>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    sources
        .as_ref()
        .map_or(&[][..], |sources| sources.as_slice())
        .serialize(serializer)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Arc<Vec<TaintSource>>>, D::Error> {
    let sources = Vec::<TaintSource>::deserialize(deserializer)?;
    Ok(TaintSet::from_recorded_sources(sources).sources)
}
