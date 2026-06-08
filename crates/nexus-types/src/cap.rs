//! Capability set: the source form of authority (attenuable, delegable).
//!
//! Capability literal: `<verb>://<scheme>/<segs>[@<predicate>]`.
//! Both verb and scheme accept `*` (and segments accept `*` / `**`) as
//! wildcards. The omnipotent set is `*://**` — meaning any verb on any
//! path. It is held by the bootstrap (root) Process and revoked from every
//! spawned child by intersection-based attenuation.

use crate::path::Path;
use crate::value::Value;
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

    fn value_num(&self) -> Option<f64> {
        self.value.trim_start_matches('$').parse::<f64>().ok()
    }

    /// True iff the request described by `input` (the op input value) at wall
    /// clock `now_millis` satisfies this predicate. Fail-closed on any missing
    /// field or type mismatch.
    pub fn eval(&self, input: &Value, now_millis: i64) -> bool {
        // `until` is a time bound on the capability itself, not an input
        // field. `@until=<ts>` reads as "valid until <ts>", i.e. authorized
        // while `now <= ts`, regardless of the literal operator used.
        if self.key == "until" {
            let Some(bound) = self.value_num() else {
                return false;
            };
            return (now_millis as f64) <= bound;
        }
        let field = match input {
            Value::Map(m) => m.get(&self.key),
            _ => None,
        };
        let Some(field) = field else { return false };
        match (&self.op, field) {
            // String equality / inequality.
            (PredOp::Eq, Value::Str(s)) => s.as_str() == self.value,
            (PredOp::Ne, Value::Str(s)) => s.as_str() != self.value,
            // Numeric comparisons against int/float fields.
            (op, Value::Int(n)) => match self.value_num() {
                Some(rhs) => Self::cmp_num(*n as f64, *op, rhs),
                None => false,
            },
            (op, Value::Float(n)) => match self.value_num() {
                Some(rhs) => Self::cmp_num(n.0, *op, rhs),
                None => false,
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

impl std::fmt::Display for Predicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            (head.to_string(), "**".to_string())
        } else {
            match head.split_once('/') {
                Some((s, b)) => (s.to_string(), b.to_string()),
                None => (head.to_string(), String::new()),
            }
        };
        validate_capability_scheme(verb, &scheme)?;
        let segments = if body.is_empty() {
            Vec::new()
        } else {
            body.split('/').map(SmolStr::from).collect()
        };
        Ok(Self {
            verb: verb.to_string(),
            scheme,
            segments,
            predicate,
        })
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
    /// `open()` time and by residual policy checks (§5/§8).
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
    /// predicate**. Used by `ResourceSelector` (§5.1), where predicates live
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
        "*" | "perform" | "read" | "write" | "subscribe" | "spawn" | "act-as" | "delegate"
    )
}

fn validate_capability_scheme(verb: &str, scheme: &str) -> Result<(), CapError> {
    if verb == "*" || scheme == "*" || scheme == "**" {
        return Ok(());
    }
    let expected = match verb {
        "perform" => Some("effect"),
        "read" | "write" | "subscribe" => Some("state"),
        "spawn" | "act-as" => Some("process"),
        "delegate" => None,
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
    pub fn iter(&self) -> std::slice::Iter<'_, Capability> {
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

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    #[test]
    fn parse_simple_cap() {
        let c = Capability::parse("perform://effect/inference/infer").unwrap();
        assert_eq!(c.verb, "perform");
        assert_eq!(c.scheme, "effect");
        assert_eq!(c.segments.len(), 2);
    }

    #[test]
    fn parse_with_predicate() {
        let c = Capability::parse("perform://effect/x/post@account=alice").unwrap();
        let pred = c.predicate.as_ref().unwrap();
        assert_eq!(pred.key, "account");
        assert_eq!(pred.op, PredOp::Eq);
        assert_eq!(pred.value, "alice");
    }

    #[test]
    fn resource_paths_and_noncanonical_verbs_are_not_capabilities() {
        assert!(Capability::parse("effect://x/post").is_err());
        assert!(Capability::parse("state://memory/alice").is_err());
        assert!(Capability::parse("append://state/events/topic").is_err());
        assert!(Capability::parse("read://effect/x/post").is_err());
        assert!(Capability::parse("perform://state/memory/alice").is_err());
    }

    #[test]
    fn predicated_cap_is_fail_closed_without_input() {
        // `covers` (no input) must NOT authorize a predicated capability.
        let c = Capability::parse("perform://effect/x/post@account=alice").unwrap();
        assert!(!c.covers("perform", &p("effect://x/post")));
        // Path matches but predicate cannot be evaluated → denied.
    }

    #[test]
    fn predicate_eq_enforced_against_input() {
        use crate::value::Value;
        use std::collections::BTreeMap;
        let c = Capability::parse("perform://effect/x/post@account=alice").unwrap();
        let mut m = BTreeMap::new();
        m.insert("account".to_string(), Value::Str("alice".into()));
        assert!(c.covers_with("perform", &p("effect://x/post"), &Value::Map(m.clone()), 0));
        m.insert("account".to_string(), Value::Str("bob".into()));
        assert!(!c.covers_with("perform", &p("effect://x/post"), &Value::Map(m), 0));
        // Missing field → denied.
        assert!(!c.covers_with("perform", &p("effect://x/post"), &Value::Null, 0));
    }

    #[test]
    fn predicate_budget_le_enforced() {
        use crate::value::Value;
        use std::collections::BTreeMap;
        let c = Capability::parse("spawn://process/alice/*@budget<=$0.10").unwrap();
        let mut m = BTreeMap::new();
        m.insert(
            "budget".to_string(),
            Value::Float(crate::value::FloatBits(0.05)),
        );
        assert!(c.covers_with(
            "spawn",
            &p("process://alice/job"),
            &Value::Map(m.clone()),
            0
        ));
        m.insert(
            "budget".to_string(),
            Value::Float(crate::value::FloatBits(0.50)),
        );
        assert!(!c.covers_with("spawn", &p("process://alice/job"), &Value::Map(m), 0));
    }

    #[test]
    fn predicate_until_is_time_bound() {
        use crate::value::Value;
        let c = Capability::parse("act-as://process/bob@until=1000").unwrap();
        // now (500) <= until (1000) → still valid.
        assert!(c.covers_with("act-as", &p("process://bob"), &Value::Null, 500));
        // now (2000) > until (1000) → expired.
        assert!(!c.covers_with("act-as", &p("process://bob"), &Value::Null, 2000));
    }

    #[test]
    fn parse_omnipotent() {
        let c = Capability::parse("*://**").unwrap();
        assert_eq!(c.verb, "*");
        // Either "*" or "**" is valid here — both are treated as the
        // any-scheme wildcard by `covers`.
        assert!(c.scheme == "*" || c.scheme == "**");
        assert_eq!(c.segments, vec![SmolStr::from("**")]);
    }

    #[test]
    fn covers_exact() {
        let c = Capability::parse("perform://effect/x/post").unwrap();
        assert!(c.covers("perform", &p("effect://x/post")));
        assert!(!c.covers("perform", &p("effect://x/reply")));
        assert!(!c.covers("read", &p("effect://x/post")));
    }

    #[test]
    fn omnipotent_covers_everything() {
        let c = Capability::parse("*://**").unwrap();
        assert!(c.covers("read", &p("state://memory/alice")));
        assert!(c.covers("write", &p("state://kernel/registry")));
        assert!(c.covers("perform", &p("effect://anything/here/and/now")));
        assert!(c.covers("spawn", &p("process://child")));
    }

    #[test]
    fn covers_wildcard_segments() {
        let c = Capability::parse("read://state/memory/alice/**").unwrap();
        assert!(c.covers("read", &p("state://memory/alice/persona")));
        assert!(c.covers("read", &p("state://memory/alice/episodic/2024/03")));
        assert!(!c.covers("read", &p("state://memory/bob/persona")));
    }

    #[test]
    fn capset_contains_all() {
        let s = CapSet::from_strs([
            "perform://effect/inference/infer",
            "perform://effect/x/post",
        ])
        .unwrap();
        assert!(s.contains_all(&[
            ("perform", p("effect://inference/infer")),
            ("perform", p("effect://x/post")),
        ]));
        assert!(!s.contains_all(&[("perform", p("effect://x/reply"))]));
    }

    #[test]
    fn intersect_attenuation_with_omnipotent_parent() {
        let parent = CapSet::from_strs(["*://**"]).unwrap();
        let granted =
            CapSet::from_strs(["perform://effect/x/post", "read://state/memory/alice/**"]).unwrap();
        let inter = parent.intersect(&granted);
        assert_eq!(inter.len(), 2);
        assert!(inter.contains("perform", &p("effect://x/post")));
    }

    #[test]
    fn intersect_drops_uncovered() {
        let parent = CapSet::from_strs(["perform://effect/inference/infer"]).unwrap();
        let granted = CapSet::from_strs([
            "perform://effect/inference/infer",
            "perform://effect/x/post", // parent doesn't have this
        ])
        .unwrap();
        let inter = parent.intersect(&granted);
        assert_eq!(inter.len(), 1);
        assert!(!inter.contains("perform", &p("effect://x/post")));
    }

    #[test]
    fn capability_subsumes_more_specific() {
        let broader = Capability::parse("read://state/memory/**").unwrap();
        let specific = Capability::parse("read://state/memory/alice/persona").unwrap();
        assert!(broader.covers_cap(&specific));
        assert!(!specific.covers_cap(&broader));
    }
}
