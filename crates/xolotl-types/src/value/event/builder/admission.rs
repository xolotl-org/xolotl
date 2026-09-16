use super::BuilderError;
use crate::value::event::Event;
use core::fmt;

/// Optional admission limits for one complete resident value document.
///
/// These count logical retained data, not exact allocator consumption. Buffer
/// capacity, collection indices, allocator headers and temporary key comparison
/// copies add overhead. Use the host's allocator policy for an absolute memory
/// ceiling. No budget is inferred from blob sizes or codec window sizes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationLimits {
    /// Sum of bytes carried by all text, byte, key and metadata data fields.
    /// Empty chunks cost nothing; rechunking does not change this sum. External
    /// blob content is not included, since the builder retains only references.
    pub max_payload_bytes: Option<u64>,
    /// Count of record begins and atoms, including document and metadata nodes.
    /// This bounds structural width even when fields and collections are empty.
    /// Data chunk events and end events do not count as additional nodes.
    pub max_nodes: Option<u64>,
    /// Maximum simultaneously open records, including document and metadata.
    /// Passed to the shared validator; no frames are preallocated from it.
    pub max_frames: Option<usize>,
}

/// A logical resident materialization dimension with explicit admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationDimension {
    /// UTF-8, raw byte and metadata field bytes retained from data events.
    PayloadBytes,
    /// Record begins and atoms independent of transport chunk boundaries.
    Nodes,
}

impl fmt::Display for MaterializationDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PayloadBytes => "payload byte",
            Self::Nodes => "node",
        })
    }
}

pub(super) struct Admission {
    limits: MaterializationLimits,
    payload_bytes: u64,
    nodes: u64,
}

impl Admission {
    pub(super) fn new(limits: MaterializationLimits) -> Self {
        Self {
            limits,
            payload_bytes: 0,
            nodes: 0,
        }
    }

    pub(super) fn admit(&mut self, event: Event<'_>) -> Result<(), BuilderError> {
        match event {
            Event::Begin(_) | Event::Atom(_) => charge(
                &mut self.nodes,
                self.limits.max_nodes,
                1,
                MaterializationDimension::Nodes,
            ),
            Event::Data(bytes) => {
                let Some(limit) = self.limits.max_payload_bytes else {
                    return Ok(());
                };
                let offered =
                    u64::try_from(bytes.len()).map_err(|_error| BuilderError::Admission {
                        dimension: MaterializationDimension::PayloadBytes,
                        limit,
                    })?;
                charge(
                    &mut self.payload_bytes,
                    Some(limit),
                    offered,
                    MaterializationDimension::PayloadBytes,
                )
            }
            Event::End(_) => Ok(()),
        }
    }
}

fn charge(
    used: &mut u64,
    limit: Option<u64>,
    amount: u64,
    dimension: MaterializationDimension,
) -> Result<(), BuilderError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let next = used
        .checked_add(amount)
        .filter(|next| *next <= limit)
        .ok_or(BuilderError::Admission { dimension, limit })?;
    *used = next;
    Ok(())
}
