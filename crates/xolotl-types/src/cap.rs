//! Capability set: the source form of authority (attenuable, delegable).
//!
//! Capability literal: `<verb>://<scheme>/<segs>[@<predicate>]`.
//! Both verb and scheme accept `*` (and segments accept `*` / `**`) as
//! wildcards. The omnipotent set is `*://**` — meaning any verb on any
//! path. It is held by the bootstrap (root) Process and revoked from every
//! spawned child by intersection-based attenuation.

use crate::path::Path;
use crate::value::Value;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;

/// One parsed capability literal.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    /// Capability verb, such as `perform`, `read`, or `spawn`.
    pub verb: String,
    /// `*` or `**` matches any scheme.
    pub scheme: String,
    /// Path segment pattern.
    pub segments: Vec<SmolStr>,
    /// Optional attenuation predicate (`@key<op>value`). When present, the
    /// capability only authorizes a request whose op input — and the wall
    /// clock for `until` — satisfies the predicate. See [`Predicate`].
    pub predicate: Option<Predicate>,
}

/// A capability attenuation predicate parsed from the `@…` suffix of a
/// capability literal, e.g. `perform://effect/x/post@account=alice` or
/// `spawn://process/alice/*@budget<=0.10` or `act-as://process/bob@until=1750000000000`.
///
/// Evaluation is fail-closed: a predicate referencing an input field that is
/// absent or of the wrong shape does **not** authorize the request. The empty
/// / unparsable case is rejected at parse time, so a stored `Some(Predicate)`
/// always carries an enforceable constraint.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// Field name looked up in the op input map. The reserved key `until`
    /// instead compares against the current wall clock (millis since epoch).
    pub key: String,
    /// Comparison operation.
    pub op: PredOp,
    /// Comparison literal. A leading `$` (currency sugar) is stripped before
    /// numeric comparison.
    pub value: String,
}

/// Predicate comparison operator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum PredOp {
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
    /// Less-than or equal.
    Le,
    /// Strictly less-than.
    Lt,
    /// Greater-than or equal.
    Ge,
    /// Strictly greater-than.
    Gt,
}

impl Predicate {
    /// Parse the raw text after `@`. Longest operators first so `<=`/`>=`
    /// win over `<`/`>`.
    pub fn parse(raw: &str) -> Result<Self, CapError> {
        let raw = raw.trim();
        for (tok, op) in [
            ("<=", PredOp::Le),
            (">=", PredOp::Ge),
            ("!=", PredOp::Ne),
            ("=", PredOp::Eq),
            ("<", PredOp::Lt),
            (">", PredOp::Gt),
        ] {
            if let Some(idx) = raw.find(tok) {
                let key = raw[..idx].trim();
                let value = raw[idx + tok.len()..].trim();
                if key.is_empty() || value.is_empty() {
                    return Err(CapError::Malformed(format!(
                        "predicate missing key or value: {}",
                        raw
                    )));
                }
                if key == "until" || matches!(op, PredOp::Le | PredOp::Lt | PredOp::Ge | PredOp::Gt)
                {
                    parse_predicate_number(value)?;
                }
                return Ok(Self {
                    key: key.to_string(),
                    op,
                    value: value.to_string(),
                });
            }
        }
        Err(CapError::Malformed(format!(
            "predicate missing operator: {}",
            raw
        )))
    }

    fn value_num(&self) -> Result<f64, CapError> {
        parse_predicate_number(&self.value)
    }

    /// True iff the request described by `input` (the op input value) at wall
    /// clock `now_millis` satisfies this predicate. Fail-closed on any missing
    /// field or type mismatch.
    pub fn eval(&self, input: &Value, now_millis: i64) -> bool {
        // `until` is a time bound on the capability itself, not an input
        // field. `@until=<ts>` reads as "valid until <ts>", i.e. authorized
        // while `now <= ts`, regardless of the literal operator used.
        if self.key == "until" {
            let Ok(bound) = self.value_num() else {
                return false;
            };
            return (now_millis as f64) <= bound;
        }
        let field = input.as_map().and_then(|map| map.get(&self.key));
        let Some(field) = field else { return false };
        match (&self.op, field.view()) {
            // String equality / inequality.
            (PredOp::Eq, crate::ValueView::Str(s)) => s == self.value,
            (PredOp::Ne, crate::ValueView::Str(s)) => s != self.value,
            // Numeric comparisons against int/float fields.
            (op, crate::ValueView::Int(n)) => match self.value_num() {
                Ok(rhs) => Self::cmp_num(n as f64, *op, rhs),
                Err(_) => false,
            },
            (op, crate::ValueView::Float(n)) => match self.value_num() {
                Ok(rhs) => Self::cmp_num(n.0, *op, rhs),
                Err(_) => false,
            },
            _ => false,
        }
    }

    fn cmp_num(lhs: f64, op: PredOp, rhs: f64) -> bool {
        match op {
            PredOp::Eq => lhs == rhs,
            PredOp::Ne => lhs != rhs,
            PredOp::Le => lhs <= rhs,
            PredOp::Lt => lhs < rhs,
            PredOp::Ge => lhs >= rhs,
            PredOp::Gt => lhs > rhs,
        }
    }
}

fn parse_predicate_number(value: &str) -> Result<f64, CapError> {
    value
        .trim_start_matches('$')
        .parse::<f64>()
        .map_err(|error| CapError::Malformed(format!("invalid predicate number: {value}: {error}")))
}

impl core::fmt::Display for Predicate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self.op {
            PredOp::Eq => "=",
            PredOp::Ne => "!=",
            PredOp::Le => "<=",
            PredOp::Lt => "<",
            PredOp::Ge => ">=",
            PredOp::Gt => ">",
        };
        write!(f, "{}{}{}", self.key, op, self.value)
    }
}

/// Capability parsing errors.
#[derive(Debug, Error)]
pub enum CapError {
    /// Capability literal is malformed.
    #[error("malformed capability: {0}")]
    Malformed(String),
}

impl Capability {
    /// Construct a capability from structured fields.
    pub fn try_new<I, S>(
        verb: impl AsRef<str>,
        scheme: impl AsRef<str>,
        segments: I,
        predicate: Option<Predicate>,
    ) -> Result<Self, CapError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let verb = verb.as_ref();
        let scheme = scheme.as_ref();
        if verb.is_empty() {
            return Err(CapError::Malformed("empty verb".into()));
        }
        if !is_capability_verb(verb) {
            return Err(CapError::Malformed(format!(
                "unsupported capability verb: {}",
                verb
            )));
        }
        validate_capability_scheme(verb, scheme)?;
        let mut parsed_segments = Vec::new();
        for segment in segments {
            let segment = segment.as_ref();
            validate_capability_segment(segment)?;
            parsed_segments.push(SmolStr::from(segment));
        }
        Ok(Self {
            verb: verb.to_string(),
            scheme: scheme.to_string(),
            segments: parsed_segments,
            predicate,
        })
    }

    /// Parse a capability literal.
    pub fn parse(s: &str) -> Result<Self, CapError> {
        let (verb, rest) = s
            .split_once("://")
            .ok_or_else(|| CapError::Malformed(format!("missing scheme separator: {}", s)))?;
        let (head, predicate) = match rest.find('@') {
            Some(idx) => (&rest[..idx], Some(Predicate::parse(&rest[idx + 1..])?)),
            None => (rest, None),
        };
        if verb.is_empty() {
            return Err(CapError::Malformed("empty verb".into()));
        }
        if !is_capability_verb(verb) {
            return Err(CapError::Malformed(format!(
                "unsupported capability verb: {}",
                verb
            )));
        }
        let (scheme, body) = if head == "*" || head == "**" {
            (head.to_string(), Some("**"))
        } else {
            match head.split_once('/') {
                Some((s, b)) => (s.to_string(), Some(b)),
                None => (head.to_string(), None),
            }
        };
        let segments = match body {
            Some("") => {
                return Err(CapError::Malformed("empty capability segment".into()));
            }
            Some(body) => body.split('/').collect(),
            None => Vec::new(),
        };
        Self::try_new(verb, &scheme, segments, predicate)
    }

    /// Check whether this capability covers (`verb`, `target`) **ignoring any
    /// predicate**. A predicated capability is never authorized through this
    /// path: callers that cannot supply the op input must treat it as
    /// non-covering (fail-closed). Use [`Capability::covers_with`] at the op
    /// gate where input and wall clock are available.
    pub fn covers(&self, verb: &str, target: &Path) -> bool {
        self.predicate.is_none() && self.covers_path(verb, target)
    }

    /// Like [`Self::covers`] but also evaluates the predicate (if any) against the
    /// op `input` and `now_millis`. This is the authoritative check used at
    /// `open()` time and by residual policy checks.
    pub fn covers_with(&self, verb: &str, target: &Path, input: &Value, now_millis: i64) -> bool {
        if !self.covers_path(verb, target) {
            return false;
        }
        match &self.predicate {
            None => true,
            Some(pred) => pred.eval(input, now_millis),
        }
    }

    fn covers_path(&self, verb: &str, target: &Path) -> bool {
        if self.verb != "*" && self.verb != verb {
            return false;
        }
        if self.scheme != "*" && self.scheme != "**" && self.scheme != target.scheme() {
            return false;
        }
        match_segments(&self.segments, target.segments())
    }

    /// Public structural match against `(verb, target)`, **ignoring any
    /// predicate**. Used by `ResourceSelector`, where predicates live
    /// in a separate `ConstraintSet` and are evaluated independently.
    pub fn verb_scheme_segments_match(&self, verb: &str, target: &Path) -> bool {
        self.covers_path(verb, target)
    }

    /// Cap A "covers" cap B (i.e. is at least as permissive). Used by
    /// intersect to test whether a parent allows a child's request.
    pub fn covers_cap(&self, other: &Capability) -> bool {
        if self.verb != "*" && self.verb != other.verb {
            return false;
        }
        if self.scheme != "*" && self.scheme != "**" && self.scheme != other.scheme {
            return false;
        }
        // Heuristic: A covers B iff every segment-pattern in B is matchable
        // by A's pattern at the same depth.
        pattern_subsumes(&self.segments, &other.segments)
    }
}

fn is_capability_verb(verb: &str) -> bool {
    matches!(
        verb,
        "*" | "perform"
            | "publish"
            | "read"
            | "write"
            | "append"
            | "subscribe"
            | "spawn"
            | "act-as"
            | "delegate"
    )
}

fn validate_capability_scheme(verb: &str, scheme: &str) -> Result<(), CapError> {
    if scheme != "*" && scheme != "**" {
        Path::try_new(scheme).map_err(|error| {
            CapError::Malformed(format!("invalid capability scheme {scheme}: {error}"))
        })?;
    }
    if verb == "*" || scheme == "*" || scheme == "**" {
        return Ok(());
    }
    let expected = match verb {
        "perform" => Some("effect"),
        "read" | "write" | "append" | "subscribe" => Some("state"),
        "spawn" | "act-as" => Some("process"),
        "publish" | "delegate" => None,
        _ => None,
    };
    if let Some(expected) = expected
        && scheme != expected
    {
        return Err(CapError::Malformed(format!(
            "{} capability must target {}://, got {}://",
            verb, expected, scheme
        )));
    }
    Ok(())
}

fn validate_capability_segment(segment: &str) -> Result<(), CapError> {
    Path::try_new("state")
        .and_then(|path| path.try_push(segment))
        .map(|_| ())
        .map_err(|error| {
            CapError::Malformed(format!("invalid capability segment {segment}: {error}"))
        })
}

fn match_segments(pat: &[SmolStr], seg: &[SmolStr]) -> bool {
    let mut pi = 0usize;
    let mut si = 0usize;
    while pi < pat.len() {
        if pat[pi].as_str() == "**" {
            if pi + 1 == pat.len() {
                return true;
            }
            for k in si..=seg.len() {
                if match_segments(&pat[pi + 1..], &seg[k..]) {
                    return true;
                }
            }
            return false;
        }
        if si >= seg.len() {
            return false;
        }
        if pat[pi].as_str() != "*" && pat[pi] != seg[si] {
            return false;
        }
        pi += 1;
        si += 1;
    }
    si == seg.len()
}

/// True if pattern `a` is at least as broad as `b`. Used during intersection.
fn pattern_subsumes(a: &[SmolStr], b: &[SmolStr]) -> bool {
    // Use match_segments where any literal in `b` is just a literal, and
    // wildcards in `b` are demoted to "any single literal" / "any chain".
    // For practical purposes treat any wildcard in `b` as matchable from `a`.
    let mut ai = 0usize;
    let mut bi = 0usize;
    while ai < a.len() {
        if a[ai].as_str() == "**" {
            if ai + 1 == a.len() {
                return true;
            }
            for k in bi..=b.len() {
                if pattern_subsumes(&a[ai + 1..], &b[k..]) {
                    return true;
                }
            }
            return false;
        }
        if bi >= b.len() {
            return false;
        }
        let aseg = a[ai].as_str();
        let bseg = b[bi].as_str();
        if aseg != "*" && aseg != bseg {
            return false;
        }
        ai += 1;
        bi += 1;
    }
    bi == b.len()
}

/// A set of capabilities.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapSet(
    /// Capabilities in this set.
    pub Vec<Capability>,
);

impl CapSet {
    /// Create an empty capability set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a capability set from string literals.
    pub fn from_strs<I, S>(items: I) -> Result<Self, CapError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v = Vec::new();
        for s in items {
            v.push(Capability::parse(s.as_ref())?);
        }
        Ok(Self(v))
    }

    /// Add one capability to the set.
    pub fn push(&mut self, c: Capability) {
        self.0.push(c);
    }

    /// Return true if any non-predicated capability covers the target.
    pub fn contains(&self, verb: &str, target: &Path) -> bool {
        self.0.iter().any(|c| c.covers(verb, target))
    }

    /// Authoritative op-gate check: a request for (`verb`, `target`) with the
    /// given op `input` at `now_millis` is permitted iff some capability
    /// covers it, predicates included.
    pub fn contains_with(&self, verb: &str, target: &Path, input: &Value, now_millis: i64) -> bool {
        self.0
            .iter()
            .any(|c| c.covers_with(verb, target, input, now_millis))
    }

    /// Return true if this set contains all required verb/path pairs.
    pub fn contains_all(&self, requireds: &[(&str, Path)]) -> bool {
        requireds.iter().all(|(v, p)| self.contains(v, p))
    }

    /// Attenuation: keep every capability `r` from `requested` that is
    /// covered by some capability in `self`.
    pub fn intersect(&self, requested: &CapSet) -> CapSet {
        let mut out = Vec::new();
        for r in &requested.0 {
            if self.0.iter().any(|p| p.covers_cap(r)) {
                out.push(r.clone());
            }
        }
        CapSet(out)
    }

    /// Iterate over capabilities.
    pub fn iter(&self) -> core::slice::Iter<'_, Capability> {
        self.0.iter()
    }
    /// Number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}://{}", self.verb, self.scheme)?;
        for s in &self.segments {
            write!(f, "/{}", s)?;
        }
        if let Some(p) = &self.predicate {
            write!(f, "@{}", p)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::p;
    use anyhow::{Context, bail, ensure};

    #[test]
    fn parse_simple_cap() -> anyhow::Result<()> {
        let c = Capability::parse("perform://effect/inference/infer")?;
        ensure!(c.verb == "perform", "unexpected verb: {}", c.verb);
        ensure!(c.scheme == "effect", "unexpected scheme: {}", c.scheme);
        ensure!(
            c.segments.len() == 2,
            "unexpected segments: {:?}",
            c.segments
        );
        Ok(())
    }

    #[test]
    fn structured_capability_builder_validates_parts() -> anyhow::Result<()> {
        let c = Capability::try_new("perform", "effect", ["inference", "infer"], None)?;
        ensure!(
            c.to_string() == "perform://effect/inference/infer",
            "unexpected capability: {c}"
        );
        let bad_segment = match Capability::try_new("perform", "effect", ["bad/slash"], None) {
            Ok(c) => bail!("bad segment was accepted: {c}"),
            Err(error) => error,
        };
        ensure!(
            bad_segment.to_string().contains("bad/slash"),
            "unexpected bad segment error: {bad_segment}"
        );
        let bad_scheme = match Capability::try_new("perform", "bad/scheme", ["x"], None) {
            Ok(c) => bail!("bad scheme was accepted: {c}"),
            Err(error) => error,
        };
        ensure!(
            bad_scheme.to_string().contains("bad/scheme"),
            "unexpected bad scheme error: {bad_scheme}"
        );
        Ok(())
    }

    #[test]
    fn parse_publish_cap() -> anyhow::Result<()> {
        let c = Capability::parse("publish://effect/search/run")?;
        ensure!(c.verb == "publish", "unexpected verb: {}", c.verb);
        ensure!(
            c.covers("publish", &p("effect://search/run")?),
            "publish did not cover path"
        );
        ensure!(
            !c.covers("perform", &p("effect://search/run")?),
            "publish covered perform"
        );
        Ok(())
    }

    #[test]
    fn parse_state_append_cap() -> anyhow::Result<()> {
        let c = Capability::parse("append://state/events/topic")?;
        ensure!(c.verb == "append", "unexpected verb: {}", c.verb);
        ensure!(
            c.covers("append", &p("state://events/topic")?),
            "append did not cover path"
        );
        ensure!(
            !c.covers("write", &p("state://events/topic")?),
            "append covered write"
        );
        Ok(())
    }

    #[test]
    fn parse_with_predicate() -> anyhow::Result<()> {
        let c = Capability::parse("perform://effect/x/post@account=alice")?;
        let pred = c.predicate.as_ref().context("predicate missing")?;
        ensure!(
            pred.key == "account",
            "unexpected predicate key: {}",
            pred.key
        );
        ensure!(
            pred.op == PredOp::Eq,
            "unexpected predicate op: {:?}",
            pred.op
        );
        ensure!(
            pred.value == "alice",
            "unexpected predicate value: {}",
            pred.value
        );
        Ok(())
    }

    #[test]
    fn resource_paths_and_noncanonical_verbs_are_not_capabilities() -> anyhow::Result<()> {
        ensure!(
            Capability::parse("effect://x/post").is_err(),
            "resource path parsed as cap"
        );
        ensure!(
            Capability::parse("state://memory/alice").is_err(),
            "state resource path parsed as cap"
        );
        ensure!(
            Capability::parse("read://effect/x/post").is_err(),
            "read effect cap was accepted"
        );
        ensure!(
            Capability::parse("perform://state/memory/alice").is_err(),
            "perform state cap was accepted"
        );
        ensure!(
            Capability::parse("perform://effect/x//post").is_err(),
            "empty capability segment was accepted"
        );
        ensure!(
            Capability::parse("perform://effect/").is_err(),
            "trailing empty capability segment was accepted"
        );
        Ok(())
    }

    #[test]
    fn predicated_cap_is_fail_closed_without_input() -> anyhow::Result<()> {
        let c = Capability::parse("perform://effect/x/post@account=alice")?;
        ensure!(
            !c.covers("perform", &p("effect://x/post")?),
            "predicated cap authorized without input"
        );
        Ok(())
    }

    #[test]
    fn predicate_eq_enforced_against_input() -> anyhow::Result<()> {
        use crate::value::Value;
        use alloc::collections::BTreeMap;
        let c = Capability::parse("perform://effect/x/post@account=alice")?;
        let mut m = BTreeMap::new();
        m.insert("account".to_string(), Value::string("alice".into()));
        ensure!(
            c.covers_with("perform", &p("effect://x/post")?, &Value::map(m.clone()), 0),
            "matching predicate was denied"
        );
        m.insert("account".to_string(), Value::string("bob".into()));
        ensure!(
            !c.covers_with("perform", &p("effect://x/post")?, &Value::map(m), 0),
            "mismatched predicate was allowed"
        );
        ensure!(
            !c.covers_with("perform", &p("effect://x/post")?, &Value::null(), 0),
            "missing predicate field was allowed"
        );
        Ok(())
    }

    #[test]
    fn predicate_budget_le_enforced() -> anyhow::Result<()> {
        use crate::value::Value;
        use alloc::collections::BTreeMap;
        let c = Capability::parse("spawn://process/alice/*@budget<=$0.10")?;
        let mut m = BTreeMap::new();
        m.insert(
            "budget".to_string(),
            Value::float(crate::value::FloatBits(0.05)),
        );
        ensure!(
            c.covers_with(
                "spawn",
                &p("process://alice/job")?,
                &Value::map(m.clone()),
                0
            ),
            "budget under limit was denied"
        );
        m.insert(
            "budget".to_string(),
            Value::float(crate::value::FloatBits(0.50)),
        );
        ensure!(
            !c.covers_with("spawn", &p("process://alice/job")?, &Value::map(m), 0),
            "budget over limit was allowed"
        );
        Ok(())
    }

    #[test]
    fn predicate_until_is_time_bound() -> anyhow::Result<()> {
        use crate::value::Value;
        let c = Capability::parse("act-as://process/bob@until=1000")?;
        ensure!(
            c.covers_with("act-as", &p("process://bob")?, &Value::null(), 500),
            "valid until predicate was denied"
        );
        ensure!(
            !c.covers_with("act-as", &p("process://bob")?, &Value::null(), 2000),
            "expired until predicate was allowed"
        );
        Ok(())
    }

    #[test]
    fn predicate_numeric_bounds_reject_bad_literals() -> anyhow::Result<()> {
        ensure!(
            Capability::parse("act-as://process/bob@until=soon").is_err(),
            "bad until literal was accepted"
        );
        ensure!(
            Capability::parse("spawn://process/alice/*@budget<=$many").is_err(),
            "bad budget literal was accepted"
        );
        Ok(())
    }

    #[test]
    fn parse_omnipotent() -> anyhow::Result<()> {
        let c = Capability::parse("*://**")?;
        ensure!(c.verb == "*", "unexpected omnipotent verb: {}", c.verb);
        ensure!(
            c.scheme == "*" || c.scheme == "**",
            "unexpected omnipotent scheme: {}",
            c.scheme
        );
        ensure!(
            c.segments == vec![SmolStr::from("**")],
            "unexpected omnipotent segments: {:?}",
            c.segments
        );
        Ok(())
    }

    #[test]
    fn covers_exact() -> anyhow::Result<()> {
        let c = Capability::parse("perform://effect/x/post")?;
        ensure!(
            c.covers("perform", &p("effect://x/post")?),
            "exact cap did not cover path"
        );
        ensure!(
            !c.covers("perform", &p("effect://x/reply")?),
            "exact cap covered sibling path"
        );
        ensure!(
            !c.covers("read", &p("effect://x/post")?),
            "perform cap covered read"
        );
        Ok(())
    }

    #[test]
    fn omnipotent_covers_everything() -> anyhow::Result<()> {
        let c = Capability::parse("*://**")?;
        ensure!(
            c.covers("read", &p("state://memory/alice")?),
            "omnipotent missed read"
        );
        ensure!(
            c.covers("write", &p("state://kernel/registry")?),
            "omnipotent missed write"
        );
        ensure!(
            c.covers("perform", &p("effect://anything/here/and/now")?),
            "omnipotent missed perform"
        );
        ensure!(
            c.covers("spawn", &p("process://child")?),
            "omnipotent missed spawn"
        );
        Ok(())
    }

    #[test]
    fn covers_wildcard_segments() -> anyhow::Result<()> {
        let c = Capability::parse("read://state/memory/alice/**")?;
        ensure!(
            c.covers("read", &p("state://memory/alice/persona")?),
            "wildcard missed child"
        );
        ensure!(
            c.covers("read", &p("state://memory/alice/episodic/2024/03")?),
            "wildcard missed deep child"
        );
        ensure!(
            !c.covers("read", &p("state://memory/bob/persona")?),
            "wildcard covered different owner"
        );
        Ok(())
    }

    #[test]
    fn capset_contains_all() -> anyhow::Result<()> {
        let s = CapSet::from_strs([
            "perform://effect/inference/infer",
            "perform://effect/x/post",
        ])?;
        ensure!(
            s.contains_all(&[
                ("perform", p("effect://inference/infer")?),
                ("perform", p("effect://x/post")?),
            ]),
            "capset did not contain expected caps"
        );
        ensure!(
            !s.contains_all(&[("perform", p("effect://x/reply")?)]),
            "capset contained sibling cap"
        );
        Ok(())
    }

    #[test]
    fn intersect_attenuation_with_omnipotent_parent() -> anyhow::Result<()> {
        let parent = CapSet::from_strs(["*://**"])?;
        let granted =
            CapSet::from_strs(["perform://effect/x/post", "read://state/memory/alice/**"])?;
        let inter = parent.intersect(&granted);
        ensure!(
            inter.len() == 2,
            "unexpected intersection size: {}",
            inter.len()
        );
        ensure!(
            inter.contains("perform", &p("effect://x/post")?),
            "intersection missed granted cap"
        );
        Ok(())
    }

    #[test]
    fn intersect_drops_uncovered() -> anyhow::Result<()> {
        let parent = CapSet::from_strs(["perform://effect/inference/infer"])?;
        let granted = CapSet::from_strs([
            "perform://effect/inference/infer",
            "perform://effect/x/post", // parent doesn't have this
        ])?;
        let inter = parent.intersect(&granted);
        ensure!(
            inter.len() == 1,
            "unexpected intersection size: {}",
            inter.len()
        );
        ensure!(
            !inter.contains("perform", &p("effect://x/post")?),
            "intersection kept uncovered cap"
        );
        Ok(())
    }

    #[test]
    fn capability_subsumes_more_specific() -> anyhow::Result<()> {
        let broader = Capability::parse("read://state/memory/**")?;
        let specific = Capability::parse("read://state/memory/alice/persona")?;
        ensure!(
            broader.covers_cap(&specific),
            "broader cap did not cover specific"
        );
        ensure!(
            !specific.covers_cap(&broader),
            "specific cap covered broader cap"
        );
        Ok(())
    }
}
