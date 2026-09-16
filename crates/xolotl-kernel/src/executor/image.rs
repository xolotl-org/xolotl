//! Lower source artifacts and prepare immutable host images.

use super::{
    BranchKind, EdgeKind, ExecutionGraph, JoinKind, NodeKind, OperationTemplate, StepRef, WaitSpec,
    machine_error,
};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use xolotl_core::{
    AnalysisSlot, IMAGE_VERSION, Join, Node as Instruction, NodeKind as Code, ProgramImage,
    ResourceRequirements,
};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, NodeId, TaintSet, TaintedFailure};

mod arena;
mod graph;
#[cfg(feature = "durable")]
pub(super) use arena::ArenaSnapshot;
use arena::ProgramArena;

#[derive(Clone)]
pub(super) enum Import {
    Vacant,
    Operation(OperationTemplate, bool),
    Step(StepRef, Option<crate::LoaderRevision>),
    Wait(WaitSpec),
    Scope(xolotl_types::Path),
    Transform(xolotl_graph::portable::Transform),
}

#[derive(Clone)]
pub(super) struct MachineProgram {
    pub nodes: Vec<Instruction<TaintedValue, TaintedFailure>>,
    pub imports: Vec<Import>,
    pub entry: u32,
    pub bindings: usize,
    #[cfg(feature = "durable")]
    pub portable: bool,
    pub durable: bool,
    pub id: [u8; 32],
    requirements: OnceLock<Result<ResourceRequirements, Failure>>,
    arena: Option<Box<ProgramArena>>,
}

/// Shared immutable host preparation, reusable across executions and threads.
/// Cloning shares instructions, constants and cached analysis; execution state is separate.
#[derive(Clone)]
pub struct PreparedProgram {
    pub(super) inner: Arc<MachineProgram>,
}

impl MachineProgram {
    /// Rebuild transient analysis only after the host validates the restored image.
    #[cfg(feature = "durable")]
    pub(super) fn from_checkpoint(
        nodes: Vec<Instruction<TaintedValue, TaintedFailure>>,
        imports: Vec<Import>,
        entry: u32,
        bindings: usize,
        portable: bool,
        durable: bool,
        id: [u8; 32],
    ) -> Self {
        Self {
            nodes,
            imports,
            entry,
            bindings,
            portable,
            durable,
            id,
            requirements: OnceLock::new(),
            arena: None,
        }
    }

    pub fn new(graph: &ExecutionGraph, config: &super::ExecutionConfig) -> Result<Self, Failure> {
        Self::lower(graph, config.max_instructions, config.bindings_per_task)
    }

    fn lower(
        graph: &ExecutionGraph,
        max_instructions: usize,
        max_bindings: usize,
    ) -> Result<Self, Failure> {
        let mut program = Self {
            nodes: Vec::new(),
            imports: Vec::new(),
            entry: 0,
            bindings: 0,
            #[cfg(feature = "durable")]
            portable: false,
            durable: false,
            id: graph.graph_hash,
            requirements: OnceLock::new(),
            arena: None,
        };
        program.entry = program.lower_graph(graph, max_instructions, max_bindings)?;
        Ok(program)
    }

    pub fn image(&self) -> ProgramImage<'_, TaintedValue, TaintedFailure> {
        ProgramImage {
            version: IMAGE_VERSION,
            id: self.id,
            nodes: &self.nodes,
            entry: self.entry,
            bindings: self.bindings,
            imports: self.imports.len(),
            durable: self.durable,
        }
    }

    pub(super) fn requirements(&self) -> Result<ResourceRequirements, Failure> {
        let mut requirements = self
            .requirements
            .get_or_init(|| self.analyze(self.entry))
            .clone()?;
        // Appended subprograms do not change control flow in the original image.
        requirements.bindings_per_task = self.bindings;
        Ok(requirements)
    }

    fn analyze(&self, entry: u32) -> Result<ResourceRequirements, Failure> {
        let mut scratch = vec![AnalysisSlot::default(); self.nodes.len()];
        let mut image = self.image();
        image.entry = entry;
        image
            .resource_requirements(&mut scratch)
            .map_err(|error| machine_error(error.to_string()))
    }

    fn import(&mut self, import: Import) -> u32 {
        let index = self.imports.len() as u32;
        self.imports.push(import);
        index
    }

    fn lower_graph(
        &mut self,
        graph: &ExecutionGraph,
        max_instructions: usize,
        max_bindings: usize,
    ) -> Result<u32, Failure> {
        let branches = graph
            .nodes
            .iter()
            .filter(|node| matches!(node.kind, NodeKind::Branch(_)))
            .count();
        if graph
            .nodes
            .len()
            .saturating_add(branches)
            .saturating_add(self.nodes.len())
            > max_instructions.min(u32::MAX as usize)
        {
            return Err(machine_error("instruction capacity exceeded"));
        }
        let base =
            u32::try_from(self.nodes.len()).map_err(|_error| machine_error("image too large"))?;
        let ids: HashMap<_, _> = graph
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.id, base + i as u32))
            .collect();
        if ids.len() != graph.nodes.len() {
            return Err(machine_error("duplicate graph node"));
        }
        let index = |id: NodeId| {
            ids.get(&id)
                .copied()
                .ok_or_else(|| machine_error("dangling graph edge"))
        };
        let links = graph::index_edges(graph, &ids, base, &mut self.bindings, max_bindings)?;
        let mut extra = Vec::new();
        for (node, links) in graph.nodes.iter().zip(links) {
            let arm = || links.arms[0].ok_or_else(|| machine_error("missing arm"));
            if !matches!(node.kind, NodeKind::Join(_)) && links.arms[1].is_some() {
                return Err(machine_error("unexpected extra arm"));
            }
            let kind = match &node.kind {
                NodeKind::Pure(value) => match links.load {
                    Some(slot) => Code::Load(slot),
                    None => Code::Literal(TaintedValue::new(value.clone(), TaintSet::author())),
                },
                NodeKind::Fail(error) => Code::Fail(TaintedFailure::pristine(error.clone())),
                NodeKind::Operation(operation) => Code::Request(self.import(Import::Operation(
                    operation.clone(),
                    links.next.is_some() || links.save.is_some(),
                ))),
                NodeKind::Step(step) => {
                    Code::Request(self.import(Import::Step(step.clone(), None)))
                }
                NodeKind::Wait(wait) => Code::Request(self.import(Import::Wait(wait.clone()))),
                NodeKind::Acting(path) => Code::Scope {
                    import: self.import(Import::Scope(path.clone())),
                    body: arm()?,
                },
                NodeKind::Branch(BranchKind::OrElse { recover }) => {
                    let recover_index = base + graph.nodes.len() as u32 + extra.len() as u32;
                    extra.push(Instruction::new(
                        Code::Request(self.import(Import::Step(recover.clone(), None))),
                        u64::from(node.id.get()),
                    ));
                    Code::Catch {
                        body: arm()?,
                        recover: recover_index,
                    }
                }
                NodeKind::Join(join) => {
                    let [Some(left), Some(right)] = links.arms else {
                        return Err(machine_error("join requires two arms"));
                    };
                    Code::Fork {
                        left,
                        right,
                        join: match join {
                            JoinKind::Both => Join::All,
                            JoinKind::Race => Join::Race,
                        },
                    }
                }
            };
            self.nodes.push(Instruction {
                kind,
                next: links.next,
                save: links.save,
                position: u64::from(node.id.get()),
            });
        }
        self.nodes.extend(extra);
        self.image()
            .validate()
            .map_err(|error| machine_error(format!("invalid image: {error:?}")))?;
        index(graph.root)
    }
}

impl PreparedProgram {
    /// Inspect the execution container allocation under the supplied host ceilings.
    /// Value payloads, compiled code and I/O buffers are outside this byte count.
    pub fn layout(
        &self,
        config: &super::ExecutionConfig,
    ) -> Result<super::ExecutionLayout, Failure> {
        config.layout(&self.inner)
    }

    /// Whether this image requires persistent execution barriers.
    pub fn is_durable(&self) -> bool {
        self.inner.durable
    }

    /// Stable compiler identity used by execution checkpoints.
    pub fn id(&self) -> [u8; 32] {
        self.inner.id
    }

    /// Prepare values once without binding the image to a particular process.
    pub fn new(program: &xolotl_graph::portable::CompiledProgram) -> Result<Self, Failure> {
        Self::from_compiled(program.clone())
    }

    /// Consume a compiled artifact without cloning its constant payloads.
    pub fn from_compiled(
        program: xolotl_graph::portable::CompiledProgram,
    ) -> Result<Self, Failure> {
        use xolotl_graph::portable::Import as Portable;
        let program = program.with_provenance();
        let image = program.image();
        let (entry, bindings, durable, id) = (image.entry, image.bindings, image.durable, image.id);
        let (nodes, imports) = program.into_parts();
        let imports = imports
            .into_iter()
            .map(|import| match import {
                Portable::Operation(operation) => Import::Operation(operation, true),
                Portable::Transform(operation) => Import::Transform(operation),
                Portable::Wait(wait) => Import::Wait(wait),
                Portable::Scope(identity) => Import::Scope(identity),
                Portable::Module(module) => Import::Step(module, None),
            })
            .collect();
        let inner = MachineProgram {
            nodes,
            imports,
            entry,
            bindings,
            #[cfg(feature = "durable")]
            portable: true,
            durable,
            id,
            requirements: OnceLock::new(),
            arena: None,
        };
        inner.requirements()?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}
