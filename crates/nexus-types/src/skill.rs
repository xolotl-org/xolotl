//! `Skill` — a named, versioned reusable unit of knowledge + procedure.
//!
//! A Skill does not add a runtime operation class. It names two things that
//! already exist: a **knowledge body** (instructions / methodology a model
//! reads) plus an optional **procedure** (a Plan the kernel executes). It lives
//! as one
//! `memory` entry under the `skills/` namespace:
//!
//! ```text
//! Skill = state://memory/<id>/skills/<name>
//!   {
//!     knowledge:    Value,          // instructions / methodology / examples
//!     procedure:    Option<Path>,   // → state://kernel/plans/<id>
//!     trigger_hint: Value,          // description / keywords / sample queries for recall
//!     scope:        SkillScope,     // Global | Identity(<id>) | Conversation(<conv>)
//!     version:      u64,
//!   }
//! ```
//!
//! Two iron rules, neither of which adds a mechanism:
//!
//! - The **knowledge body** is injected through the *same* recall path as any
//!   memory: Context Assembly does a vector search + rerank over
//!   the current query, and `skills/` entries whose `trigger_hint` matches are
//!   injected. Irrelevant Skills never enter the prompt and never burn budget.
//! - The **procedure** runs through the *same* path as a Plan: the
//!   stored `procedure` Path points at a serialized Plan/`Do<A>`
//!   (`state://kernel/plans/<id>`) which the memory/plan layer validates
//!   (target / capability / schema) and **compiles to `Do<A>` on load**, then
//!   runs *inside the calling Process*, inheriting its capabilities and budget.
//!   A Skill grants **no** privilege to bypass capability checks.
//!
//! This type is the data descriptor only. It deliberately stores `procedure`
//! as a `Path` reference (not an inlined Plan): inlining a `Plan`/`Do<A>` here
//! would force `nexus-types` to depend on `nexus-graph`, inverting the layering
//! The memory/plan layer (`nexus-plan`, which *does* see the Plan
//! type) is responsible for resolving that Path and compiling the Plan on load.

use crate::path::Path;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The visibility / applicability scope of a [`Skill`]. Determines how
/// broadly recall may surface it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillScope {
    /// Available to every identity / conversation.
    #[default]
    Global,
    /// Scoped to a single identity (`state://memory/<id>/skills/*`).
    Identity(String),
    /// Scoped to a single conversation.
    Conversation(String),
}

/// A named, versioned reusable unit of knowledge + (optional) procedure.
///
/// Stored as one memory entry at `state://memory/<id>/skills/<name>`. The
/// `knowledge` half is injected like a dynamic prompt fragment by recall; the
/// `procedure` half (when present) references a Plan compiled and run on load.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Skill {
    /// Instructions / methodology / examples — the reusable prompt fragment
    /// recall injects.
    pub knowledge: Value,
    /// Optional reference to a serialized Plan/`Do<A>` at
    /// `state://kernel/plans/<id>`. Compiled to `Do<A>` on load by the
    /// memory/plan layer; runs in the calling Process under its capabilities and
    /// budget. `None` = knowledge-only Skill (pure dynamic prompt).
    #[serde(default)]
    pub procedure: Option<Path>,
    /// Description / keywords / sample queries used for retrieval — decides when
    /// this Skill is recalled.
    #[serde(default)]
    pub trigger_hint: Value,
    /// Visibility scope.
    #[serde(default)]
    pub scope: SkillScope,
    /// Monotonic version; bumped on each edit so Console can review / roll back
    ///    #[serde(default)]
    pub version: u64,
}

impl Skill {
    /// A knowledge-only Skill (no procedure) at version 1, global scope.
    pub fn knowledge_only(knowledge: impl Into<Value>, trigger_hint: impl Into<Value>) -> Self {
        Self {
            knowledge: knowledge.into(),
            procedure: None,
            trigger_hint: trigger_hint.into(),
            scope: SkillScope::Global,
            version: 1,
        }
    }

    /// Whether this Skill carries an executable procedure.
    pub fn has_procedure(&self) -> bool {
        self.procedure.is_some()
    }

    /// Project to a `Value` map for storage / wire (mirrors the convention used
    /// by [`crate::device::EffectProvider`]). The stored shape matches the
    /// `state://memory/<id>/skills/<name>` schema.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("knowledge".into(), self.knowledge.clone());
        if let Some(p) = &self.procedure {
            m.insert("procedure".into(), Value::Str(p.to_string()));
        }
        m.insert("trigger_hint".into(), self.trigger_hint.clone());
        m.insert("scope".into(), scope_to_value(&self.scope));
        m.insert("version".into(), Value::Int(self.version as i64));
        Value::Map(m)
    }

    /// Reconstruct a Skill from its `Value` map projection. Returns `None` if a
    /// required field is missing or malformed.
    pub fn from_value(v: &Value) -> Option<Self> {
        let m = v.as_map()?;
        let knowledge = m.get("knowledge").cloned().unwrap_or(Value::Null);
        let procedure = match m.get("procedure").and_then(|v| v.as_str()) {
            Some(s) => Some(Path::parse(s).ok()?),
            None => None,
        };
        let trigger_hint = m.get("trigger_hint").cloned().unwrap_or(Value::Null);
        let scope = m.get("scope").map(scope_from_value).unwrap_or_default();
        let version = m.get("version").and_then(|v| v.as_int()).unwrap_or(0) as u64;
        Some(Self {
            knowledge,
            procedure,
            trigger_hint,
            scope,
            version,
        })
    }
}

fn scope_to_value(s: &SkillScope) -> Value {
    match s {
        SkillScope::Global => Value::Str("global".into()),
        SkillScope::Identity(id) => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("identity".into()));
            m.insert("id".into(), Value::Str(id.clone()));
            Value::Map(m)
        }
        SkillScope::Conversation(conv) => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("conversation".into()));
            m.insert("id".into(), Value::Str(conv.clone()));
            Value::Map(m)
        }
    }
}

fn scope_from_value(v: &Value) -> SkillScope {
    match v {
        Value::Str(s) if s == "global" => SkillScope::Global,
        Value::Map(m) => {
            let id = m
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            match m.get("kind").and_then(|v| v.as_str()) {
                Some("identity") => SkillScope::Identity(id),
                Some("conversation") => SkillScope::Conversation(id),
                _ => SkillScope::Global,
            }
        }
        _ => SkillScope::Global,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_only_roundtrip() {
        let s = Skill::knowledge_only(
            Value::Str("when summarizing, lead with the decision".into()),
            Value::Str("summary, tl;dr".into()),
        );
        assert!(!s.has_procedure());
        let v = s.to_value();
        let back = Skill::from_value(&v).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn full_skill_roundtrip() {
        let s = Skill {
            knowledge: Value::Str("methodology body".into()),
            procedure: Some(Path::parse("state://kernel/plans/triage-v2").unwrap()),
            trigger_hint: Value::Str("triage incoming issue".into()),
            scope: SkillScope::Identity("alice".into()),
            version: 7,
        };
        assert!(s.has_procedure());
        let v = s.to_value();
        let back = Skill::from_value(&v).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn conversation_scope_roundtrip() {
        let s = Skill {
            knowledge: Value::Null,
            procedure: None,
            trigger_hint: Value::Null,
            scope: SkillScope::Conversation("conv-42".into()),
            version: 3,
        };
        let back = Skill::from_value(&s.to_value()).unwrap();
        assert_eq!(s, back);
        assert_eq!(back.scope, SkillScope::Conversation("conv-42".into()));
    }

    #[test]
    fn default_scope_is_global() {
        assert_eq!(SkillScope::default(), SkillScope::Global);
        let s = Skill::default();
        assert_eq!(s.scope, SkillScope::Global);
        assert_eq!(s.version, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let s = Skill {
            knowledge: Value::Str("k".into()),
            procedure: Some(Path::parse("state://kernel/plans/p").unwrap()),
            trigger_hint: Value::Str("t".into()),
            scope: SkillScope::Global,
            version: 1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Skill = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
