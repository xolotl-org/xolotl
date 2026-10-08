//! Capability set: the source form of authority (attenuable, delegable).
//!
//! Capability literal: `<verb>://<scheme>/<segs>[#<method>][@<predicate>]` for local
//! paths, or `<verb>://path://<cluster>/<scheme>/<segs>[#<method>][@<predicate>]`
//! for cluster-qualified paths.
//! Both verb and scheme accept `*` (and segments accept `*` / `**`) as
//! wildcards. The omnipotent set is `*://**` — meaning any verb on any
//! path. It is held by the bootstrap (root) Process and revoked from every
//! spawned child by intersection-based attenuation.

use crate::path::{Path, match_segments, pattern_subsumes_segments};
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
    /// Capability verb, such as `perform`, `read`, or `spawn`. `spawn-with`
    /// authorizes a host to propagate a resource method into a child, separately
    /// from permission to call that method or create a named process.
    pub verb: String,
    /// `None` selects only local paths. `Some("*")` selects any clustered
    /// path, and any other value selects one exact cluster. Only the canonical
    /// root capability `*://**` spans local and clustered paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// `*` or `**` matches any scheme.
    pub scheme: String,
    /// Path segment pattern.
    pub segments: Vec<SmolStr>,
    /// Optional stable resource method name. A capability without a method
    /// covers every method in its verb/path scope. Non-method checks cannot
    /// consume a method-restricted capability without naming the method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Optional attenuation predicate (`@key<op>value`). When present, the
    /// capability only authorizes a request whose op input — and the wall
    /// clock for `until` — satisfies the predicate. See [`Predicate`].
    pub predicate: Option<Predicate>,
}

/// A capability attenuation predicate parsed from the `@…` suffix of a
/// capability literal, e.g. `perform://effect/x/post@account=alice` or
/// `spawn://process/alice/*@budget<=0.10` or `act-as://identity/bob@until=1750000000000`.
///
/// Evaluation is fail-closed: a predicate referencing an input field that is
/// absent or of the wrong shape does **not** authorize the request. The empty
/// / unparsable case is rejected at parse time, so a stored `Some(Predicate)`
/// always carries an enforceable constraint.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
    /// Parse the raw text after `@`. The first operator separates the key
    /// from its value; two-character operators win at that position.
    pub fn parse(raw: &str) -> Result<Self, CapError> {
        let raw = raw.trim();
        let idx = raw
            .find(['<', '>', '!', '='])
            .ok_or_else(|| CapError::Malformed(format!("predicate missing operator: {raw}")))?;
        let tail = &raw[idx..];
        let (width, op) = if tail.starts_with("<=") {
            (2, PredOp::Le)
        } else if tail.starts_with(">=") {
            (2, PredOp::Ge)
        } else if tail.starts_with("!=") {
            (2, PredOp::Ne)
        } else {
            match tail.as_bytes()[0] {
                b'=' => (1, PredOp::Eq),
                b'<' => (1, PredOp::Lt),
                b'>' => (1, PredOp::Gt),
                _ => {
                    return Err(CapError::Malformed(format!(
                        "invalid predicate operator: {raw}"
                    )));
                }
            }
        };
        let key = raw[..idx].trim();
        let value = raw[idx + width..].trim();
        if key.is_empty() || value.is_empty() {
            return Err(CapError::Malformed(format!(
                "predicate missing key or value: {raw}"
            )));
        }
        if key == "until" {
            if op != PredOp::Eq {
                return Err(CapError::Malformed("until predicate must use '='".into()));
            }
            value.parse::<i64>().map_err(|error| {
                CapError::Malformed(format!("invalid until milliseconds: {value}: {error}"))
            })?;
        } else if matches!(op, PredOp::Le | PredOp::Lt | PredOp::Ge | PredOp::Gt) {
            parse_predicate_number(value)?;
        }
        Ok(Self {
            key: key.to_string(),
            op,
            value: value.to_string(),
        })
    }

    fn value_num(&self) -> Result<f64, CapError> {
        parse_predicate_number(&self.value)
    }

    /// True iff the request described by `input` (the op input value) at wall
    /// clock `now_millis` satisfies this predicate. Fail-closed on any missing
    /// field or type mismatch.
    pub fn eval(&self, input: &Value, now_millis: i64) -> bool {
        // `until` is a time bound on the capability itself, not an input
        // field. `@until=<ts>` reads as "valid until <ts>" in exact i64
        // milliseconds, including the final millisecond.
        if self.key == "until" {
            if self.op != PredOp::Eq {
                return false;
            }
            let Ok(bound) = self.value.parse::<i64>() else {
                return false;
            };
            return now_millis <= bound;
        }
        let field = input.as_map().and_then(|map| map.get(&self.key));
        let Some(field) = field else { return false };
        match (&self.op, field.view()) {
            // String equality / inequality.
            (PredOp::Eq, crate::ValueView::Str(s)) => s == self.value,
            (PredOp::Ne, crate::ValueView::Str(s)) => s != self.value,
            // Preserve the input's numeric type. Converting an i64 to f64
            // would round distinct integers above 2^53 into one authority
            // boundary; integer fields therefore require integer literals.
            (op, crate::ValueView::Int(n)) => {
                parse_predicate_integer(&self.value).is_ok_and(|rhs| Self::cmp_int(n, *op, rhs))
            }
            (op, crate::ValueView::Float(n)) => {
                n.0.is_finite()
                    && self
                        .value_num()
                        .is_ok_and(|rhs| Self::cmp_num(n.0, *op, rhs))
            }
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

    fn cmp_int(lhs: i64, op: PredOp, rhs: i64) -> bool {
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

fn predicate_number_text(value: &str) -> &str {
    value.strip_prefix('$').unwrap_or(value)
}

fn parse_predicate_integer(value: &str) -> Result<i64, CapError> {
    predicate_number_text(value)
        .parse::<i64>()
        .map_err(|error| {
            CapError::Malformed(format!("invalid predicate integer: {value}: {error}"))
        })
}

fn parse_predicate_number(value: &str) -> Result<f64, CapError> {
    let number = predicate_number_text(value)
        .parse::<f64>()
        .map_err(|error| {
            CapError::Malformed(format!("invalid predicate number: {value}: {error}"))
        })?;
    if !number.is_finite() {
        return Err(CapError::Malformed(format!(
            "predicate number must be finite: {value}"
        )));
    }
    Ok(number)
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
            cluster: None,
            scheme: scheme.to_string(),
            segments: parsed_segments,
            method: None,
            predicate,
        })
    }

    /// Restrict this capability to one stable method name. A separate
    /// capability may be supplied for each alternative method.
    pub fn try_with_method(mut self, method: impl Into<String>) -> Result<Self, CapError> {
        let method = method.into();
        if method.is_empty() {
            return Err(CapError::Malformed("empty capability method".into()));
        }
        self.method = Some(method);
        Ok(self)
    }

    /// Qualify this capability for one cluster, or for every clustered path
    /// with `*`. The unqualified form always remains local.
    pub fn try_with_cluster(mut self, cluster: &str) -> Result<Self, CapError> {
        if cluster != "*" {
            Path::try_new("state")
                .and_then(|path| path.try_with_cluster(cluster))
                .map_err(|error| {
                    CapError::Malformed(format!("invalid capability cluster {cluster}: {error}"))
                })?;
        }
        self.cluster = Some(cluster.to_string());
        Ok(self)
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
        if rest
            .find('@')
            .is_some_and(|index| rest[index + 1..].contains('#'))
        {
            return Err(CapError::Malformed(
                "capability method must precede the predicate".into(),
            ));
        }
        let (head, method) = match head.split_once('#') {
            Some((head, method)) => (head, Some(decode_method(method)?)),
            None => (head, None),
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
        let (cluster, head) = match head.strip_prefix("path://") {
            Some(clustered) => {
                let (cluster, rest) = clustered.split_once('/').ok_or_else(|| {
                    CapError::Malformed(format!("clustered capability missing scheme: {s}"))
                })?;
                (Some(cluster), rest)
            }
            None => (None, head),
        };
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
        let mut capability = Self::try_new(verb, &scheme, segments, predicate)?;
        if let Some(method) = method {
            capability = capability.try_with_method(method)?;
        }
        match cluster {
            Some(cluster) => capability.try_with_cluster(cluster),
            None => Ok(capability),
        }
    }

    /// Check whether this capability covers (`verb`, `target`) **ignoring any
    /// predicate**. A predicated capability is never authorized through this
    /// path: callers that cannot supply the op input must treat it as
    /// non-covering (fail-closed). Use [`Capability::covers_with`] at the op
    /// gate where input and wall clock are available.
    pub fn covers(&self, verb: &str, target: &Path) -> bool {
        self.method.is_none() && self.predicate.is_none() && self.covers_path(verb, target)
    }

    /// Non-predicated coverage of a concrete method.
    pub fn covers_method(&self, verb: &str, target: &Path, method: &str) -> bool {
        self.predicate.is_none() && self.matches_method(verb, target, method)
    }

    /// Like [`Self::covers`] but also evaluates the predicate (if any) against the
    /// op `input` and `now_millis`. This is the authoritative check used at
    /// `open()` time and by residual policy checks.
    pub fn covers_with(&self, verb: &str, target: &Path, input: &Value, now_millis: i64) -> bool {
        if self.method.is_some() || !self.covers_path(verb, target) {
            return false;
        }
        match &self.predicate {
            None => true,
            Some(pred) => pred.eval(input, now_millis),
        }
    }

    fn covers_path(&self, verb: &str, target: &Path) -> bool {
        if !self.cluster_covers_path(target) {
            return false;
        }
        if self.verb != "*" && self.verb != verb {
            return false;
        }
        if self.scheme != "*" && self.scheme != "**" && self.scheme != target.scheme() {
            return false;
        }
        match_segments(&self.segments, target.segments())
    }

    fn is_global_root(&self) -> bool {
        self.cluster.is_none()
            && self.verb == "*"
            && self.scheme == "**"
            && self.segments.len() == 1
            && self.segments[0].as_str() == "**"
    }

    fn cluster_covers_path(&self, target: &Path) -> bool {
        if self.is_global_root() {
            return true;
        }
        match (self.cluster.as_deref(), target.cluster()) {
            (None, None) | (Some("*"), Some(_)) => true,
            (Some(cluster), Some(target)) => cluster == target,
            _ => false,
        }
    }

    fn cluster_covers_cap(&self, other: &Self) -> bool {
        if self.is_global_root() {
            return true;
        }
        match (self.cluster.as_deref(), other.cluster.as_deref()) {
            (None, None) | (Some("*"), Some(_)) => true,
            (Some(parent), Some(child)) => parent == child,
            _ => false,
        }
    }

    /// Public structural match against `(verb, target)`, ignoring predicates.
    /// A named-method capability cannot authorize a call with no method.
    pub fn matches_structure(&self, verb: &str, target: &Path) -> bool {
        self.method.is_none() && self.covers_path(verb, target)
    }

    /// Match only the verb and path for bookkeeping over an already admitted
    /// method. This must not be used as an authorization check.
    pub fn matches_path_structure(&self, verb: &str, target: &Path) -> bool {
        self.covers_path(verb, target)
    }

    /// Structural match for one method, ignoring only the predicate.
    pub fn matches_method(&self, verb: &str, target: &Path, method: &str) -> bool {
        self.covers_path(verb, target)
            && self
                .method
                .as_deref()
                .is_none_or(|selected| selected == method)
    }

    /// Advisory preflight with no operation input: test structure and reject a
    /// time bound already expired. Input predicates remain unresolved and must
    /// be checked by [`Self::covers_with`] at the actual operation gate.
    pub fn matches_preflight(&self, verb: &str, target: &Path, now_millis: i64) -> bool {
        self.method.is_none() && self.matches_preflight_path(verb, target, now_millis)
    }

    /// Advisory preflight for a concrete method. Input predicates remain
    /// residual until the operation has its real input.
    pub fn matches_method_preflight(
        &self,
        verb: &str,
        target: &Path,
        method: &str,
        now_millis: i64,
    ) -> bool {
        self.method
            .as_deref()
            .is_none_or(|selected| selected == method)
            && self.matches_preflight_path(verb, target, now_millis)
    }

    fn matches_preflight_path(&self, verb: &str, target: &Path, now_millis: i64) -> bool {
        self.covers_path(verb, target)
            && !self.predicate.as_ref().is_some_and(|predicate| {
                predicate.key == "until" && !predicate.eval(&Value::null(), now_millis)
            })
    }

    /// Whether this capability permits every request permitted by `other`.
    /// An input predicate may only be retained exactly when attenuating;
    /// comparing arbitrary predicates for logical implication is deliberately
    /// outside the capability grammar.
    pub fn covers_cap(&self, other: &Capability) -> bool {
        self.covers_cap_pattern(other)
            && (self.predicate.is_none() || self.predicate == other.predicate)
    }

    /// Structural cluster, verb, scheme and path coverage, ignoring predicates.
    /// Useful when an application carries the parent's predicate into a
    /// separate constraint set before deriving a child grant. This alone is
    /// insufficient to authorize attenuation.
    pub fn covers_cap_pattern(&self, other: &Capability) -> bool {
        self.covers_cap_path_pattern(other)
            && (self.method.is_none() || self.method == other.method)
    }

    /// Structural path coverage without method or predicate attenuation.
    pub fn covers_cap_path_pattern(&self, other: &Capability) -> bool {
        if !self.cluster_covers_cap(other) {
            return false;
        }
        if self.verb != "*" && self.verb != other.verb {
            return false;
        }
        if self.scheme != "*" && self.scheme != "**" && self.scheme != other.scheme {
            return false;
        }
        pattern_subsumes_segments(&self.segments, &other.segments)
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
            | "spawn-with"
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
    // Callable method categories describe the operation, independently of an
    // application-defined Resource scheme. These two verbs name kernel-owned
    // identity and process domains rather than a Resource method category.
    let expected = match verb {
        "spawn" => Some("process"),
        "act-as" => Some("identity"),
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

    /// Non-predicated coverage of a named resource method.
    pub fn contains_method(&self, verb: &str, target: &Path, method: &str) -> bool {
        self.0
            .iter()
            .any(|capability| capability.covers_method(verb, target, method))
    }

    /// Whether some selector survives input-free preflight. Input predicates
    /// are still unresolved; this never authorizes a concrete operation.
    pub fn matches_preflight(&self, verb: &str, target: &Path, now_millis: i64) -> bool {
        self.0
            .iter()
            .any(|capability| capability.matches_preflight(verb, target, now_millis))
    }

    /// Advisory preflight for a named resource method.
    pub fn matches_method_preflight(
        &self,
        verb: &str,
        target: &Path,
        method: &str,
        now_millis: i64,
    ) -> bool {
        self.0
            .iter()
            .any(|capability| capability.matches_method_preflight(verb, target, method, now_millis))
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

    /// Attenuation: keep each requested capability only when a parent covers
    /// its entire path language and its predicate. A predicated parent cannot
    /// authorize an unpredicated child.
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
        write!(f, "{}://", self.verb)?;
        if let Some(cluster) = &self.cluster {
            write!(f, "path://{cluster}/")?;
        }
        write!(f, "{}", self.scheme)?;
        for s in &self.segments {
            write!(f, "/{}", s)?;
        }
        if let Some(method) = &self.method {
            f.write_str("#")?;
            for byte in method.bytes() {
                if method_unreserved(byte) {
                    write!(f, "{}", byte as char)?;
                } else {
                    write!(f, "%{byte:02X}")?;
                }
            }
        }
        if let Some(p) = &self.predicate {
            write!(f, "@{}", p)?;
        }
        Ok(())
    }
}

fn decode_method(encoded: &str) -> Result<String, CapError> {
    if encoded.is_empty() {
        return Err(CapError::Malformed("empty capability method".into()));
    }
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut chars = encoded.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let high = chars.next().and_then(canonical_hex);
            let low = chars.next().and_then(canonical_hex);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(CapError::Malformed(
                    "invalid capability method escape".into(),
                ));
            };
            let decoded = (high << 4) | low;
            if method_unreserved(decoded) {
                return Err(CapError::Malformed(
                    "noncanonical capability method escape".into(),
                ));
            }
            bytes.push(decoded);
        } else if method_unreserved(byte) {
            bytes.push(byte);
        } else {
            return Err(CapError::Malformed(
                "unescaped capability method byte".into(),
            ));
        }
    }
    String::from_utf8(bytes)
        .map_err(|_error| CapError::Malformed("capability method is not UTF-8".into()))
}

fn method_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

fn canonical_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
    fn callable_authority_is_independent_of_resource_scheme() -> anyhow::Result<()> {
        let target = p("device://lab/thermostat")?;
        for verb in ["perform", "read", "write", "append", "subscribe", "publish"] {
            let cap = Capability::parse(&format!("{verb}://device/lab/thermostat"))?;
            ensure!(cap.covers(verb, &target));
            ensure!(!cap.covers("spawn", &target));
        }
        ensure!(Capability::parse("act-as://device/lab/thermostat").is_err());
        ensure!(Capability::parse("spawn://device/lab/thermostat").is_err());
        Ok(())
    }

    #[test]
    fn named_method_literal_is_canonical_and_unambiguous() -> anyhow::Result<()> {
        let method = "read#private@v1/秘密";
        let capability = Capability::parse(
            "read://state/accounts/alice#read%23private%40v1%2F%E7%A7%98%E5%AF%86@tenant=alice",
        )?;
        ensure!(capability.method.as_deref() == Some(method));
        ensure!(
            capability.to_string()
                == "read://state/accounts/alice#read%23private%40v1%2F%E7%A7%98%E5%AF%86@tenant=alice"
        );
        ensure!(Capability::parse(&capability.to_string())? == capability);
        for invalid in [
            "read://state/x#",
            "read://state/x#read#private",
            "read://state/x#read%2fprivate",
            "read://state/x#%72ead",
            "read://state/x#%FF",
            "read://state/x@tenant=alice#read",
        ] {
            ensure!(Capability::parse(invalid).is_err(), "accepted {invalid}");
        }
        Ok(())
    }

    #[test]
    fn named_method_requires_method_aware_checks_and_attenuates() -> anyhow::Result<()> {
        let path = p("state://accounts/alice")?;
        let narrow = CapSet::from_strs(["read://state/accounts/alice#read"])?;
        let broad = CapSet::from_strs(["read://state/accounts/alice"])?;
        ensure!(narrow.contains_method("read", &path, "read"));
        ensure!(!narrow.contains_method("read", &path, "read_secret"));
        ensure!(!narrow.contains("read", &path));
        ensure!(!narrow.matches_preflight("read", &path, 0));
        ensure!(broad.intersect(&narrow) == narrow);
        ensure!(narrow.intersect(&broad).is_empty());
        Ok(())
    }

    #[test]
    fn attenuation_cannot_turn_one_segment_into_any_depth() -> anyhow::Result<()> {
        let parent = CapSet::from_strs(["read://state/memory/*"])?;
        let requested = CapSet::from_strs(["read://state/memory/**"])?;
        let child = parent.intersect(&requested);
        ensure!(
            child.is_empty(),
            "attenuation widened a single-segment grant"
        );
        ensure!(
            !child.contains("read", &p("state://memory/alice/secret")?),
            "attenuated child reached a path its parent could not reach"
        );
        Ok(())
    }

    #[test]
    fn attenuation_cannot_discard_parent_predicate() -> anyhow::Result<()> {
        let parent = CapSet::from_strs(["read://state/memory/**@account=alice"])?;
        let requested = CapSet::from_strs(["read://state/memory/**"])?;
        ensure!(
            parent.intersect(&requested).is_empty(),
            "attenuation discarded the parent's input predicate"
        );
        let same = CapSet::from_strs(["read://state/memory/**@account=alice"])?;
        ensure!(parent.intersect(&same) == same);
        Ok(())
    }

    #[test]
    fn structural_coverage_never_exceeds_parent_on_small_patterns() -> anyhow::Result<()> {
        fn sequences(alphabet: &[&str], max_len: usize) -> Vec<Vec<SmolStr>> {
            let mut result = vec![Vec::new()];
            let mut layer = vec![Vec::new()];
            for _ in 0..max_len {
                let mut next = Vec::new();
                for prefix in &layer {
                    for element in alphabet {
                        let mut sequence = prefix.clone();
                        sequence.push(SmolStr::from(*element));
                        next.push(sequence);
                    }
                }
                result.extend(next.iter().cloned());
                layer = next;
            }
            result
        }

        let patterns = sequences(&["a", "b", "*", "**"], 4);
        let targets = sequences(&["a", "b"], 6);
        for parent in &patterns {
            for child in &patterns {
                if !pattern_subsumes_segments(parent, child) {
                    continue;
                }
                for target in &targets {
                    ensure!(
                        !match_segments(child, target) || match_segments(parent, target),
                        "structural coverage widened authority: parent={parent:?}, child={child:?}, target={target:?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn nested_globstar_attenuation_uses_bounded_stack() -> anyhow::Result<()> {
        let mut parent = Vec::new();
        let mut child = Vec::new();
        for _ in 0..256 {
            parent.push(SmolStr::from("**"));
            child.push(SmolStr::from("a"));
        }
        ensure!(pattern_subsumes_segments(&parent, &child));
        let mut broader = child;
        broader.push(SmolStr::from("**"));
        ensure!(pattern_subsumes_segments(&parent, &broader));
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
            Capability::parse("delete://effect/x/post").is_err(),
            "unknown capability verb was accepted"
        );
        ensure!(
            Capability::parse("act-as://process/alice").is_err(),
            "process resource parsed as an acting identity"
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
        let c = Capability::parse("act-as://identity/bob@until=1000")?;
        ensure!(
            c.covers_with("act-as", &p("identity://bob")?, &Value::null(), 500),
            "valid until predicate was denied"
        );
        ensure!(
            !c.covers_with("act-as", &p("identity://bob")?, &Value::null(), 2000),
            "expired until predicate was allowed"
        );
        let exact = Capability::parse("act-as://identity/bob@until=9007199254740993")?;
        ensure!(exact.covers_with(
            "act-as",
            &p("identity://bob")?,
            &Value::null(),
            9_007_199_254_740_993
        ));
        ensure!(!exact.covers_with(
            "act-as",
            &p("identity://bob")?,
            &Value::null(),
            9_007_199_254_740_994
        ));
        Ok(())
    }

    #[test]
    fn predicate_numeric_bounds_reject_bad_literals() -> anyhow::Result<()> {
        ensure!(
            Capability::parse("act-as://identity/bob@until=soon").is_err(),
            "bad until literal was accepted"
        );
        for malformed in [
            "act-as://identity/bob@until<=1000",
            "act-as://identity/bob@until=1000.5",
            "act-as://identity/bob@until=inf",
            "act-as://identity/bob@until=9223372036854775808",
            "spawn://process/alice/*@budget<=NaN",
            "spawn://process/alice/*@budget<=inf",
        ] {
            ensure!(
                Capability::parse(malformed).is_err(),
                "accepted {malformed}"
            );
        }
        ensure!(
            Capability::parse("spawn://process/alice/*@budget<=$many").is_err(),
            "bad budget literal was accepted"
        );
        let constructed = Predicate {
            key: "until".into(),
            op: PredOp::Ge,
            value: "1000".into(),
        };
        ensure!(!constructed.eval(&Value::null(), 0));
        let string_value = Predicate::parse("account=alice<=suffix")?;
        ensure!(string_value.key == "account");
        ensure!(string_value.op == PredOp::Eq);
        ensure!(string_value.value == "alice<=suffix");
        let exact = Predicate::parse("count<=9007199254740993")?;
        let input = Value::map(alloc::collections::BTreeMap::from([(
            "count".into(),
            Value::integer(9_007_199_254_740_994),
        )]));
        ensure!(!exact.eval(&input, 0), "integer threshold was rounded up");
        let fractional = Predicate::parse("count<10.5")?;
        ensure!(!fractional.eval(&input, 0));
        let nonfinite = Predicate::parse("score!=1")?;
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let input = Value::map(alloc::collections::BTreeMap::from([(
                "score".into(),
                Value::float(crate::value::FloatBits(value)),
            )]));
            ensure!(!nonfinite.eval(&input, 0));
        }
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
    fn capability_cluster_scope_is_explicit() -> anyhow::Result<()> {
        let local = Capability::parse("perform://effect/x/post")?;
        let phone = Capability::parse("perform://path://phone/effect/x/post")?;
        let any_cluster = Capability::parse("perform://path://*/effect/x/post")?;
        let local_path = p("effect://x/post")?;
        let phone_path = p("path://phone/effect/x/post")?;
        let tablet_path = p("path://tablet/effect/x/post")?;

        ensure!(local.covers("perform", &local_path));
        ensure!(!local.covers("perform", &phone_path));
        ensure!(!phone.covers("perform", &local_path));
        ensure!(phone.covers("perform", &phone_path));
        ensure!(!phone.covers("perform", &tablet_path));
        ensure!(!any_cluster.covers("perform", &local_path));
        ensure!(any_cluster.covers("perform", &phone_path));
        ensure!(any_cluster.covers("perform", &tablet_path));
        ensure!(phone.to_string() == "perform://path://phone/effect/x/post");
        ensure!(Capability::parse(&phone.to_string())? == phone);
        ensure!(Capability::parse(&any_cluster.to_string())? == any_cluster);
        ensure!(Capability::parse(&local.to_string())? == local);
        let scheme_named_cluster = Capability::parse("perform://path://state/effect/x/post")?;
        ensure!(
            scheme_named_cluster.covers("perform", &Path::parse("path://state/effect/x/post")?),
            "scheme-named cluster was not addressable"
        );
        ensure!(Capability::parse("perform://path:///effect/x/post").is_err());

        // The capability grammar explicitly delimits cluster and scheme, so
        // it can represent a clustered custom scheme without Path::parse.
        let custom = Capability::parse("publish://path://phone/custom/x")?;
        let custom_path = Path::try_new("custom")?
            .try_with_cluster("phone")?
            .try_push("x")?;
        ensure!(custom.covers("publish", &custom_path));
        ensure!(Path::parse(&custom_path.to_string())? == custom_path);
        ensure!(Capability::parse(&custom.to_string())? == custom);
        Ok(())
    }

    #[test]
    fn cluster_attenuation_never_widens_authority() -> anyhow::Result<()> {
        let local = Capability::parse("read://state/memory/**")?;
        let phone = Capability::parse("read://path://phone/state/memory/**")?;
        let tablet = Capability::parse("read://path://tablet/state/memory/**")?;
        let clustered = Capability::parse("read://path://*/state/memory/**")?;
        let root = Capability::parse("*://**")?;

        ensure!(!local.covers_cap(&phone));
        ensure!(!phone.covers_cap(&local));
        ensure!(!phone.covers_cap(&tablet));
        ensure!(!phone.covers_cap(&clustered));
        ensure!(clustered.covers_cap(&phone));
        ensure!(clustered.covers_cap(&tablet));
        ensure!(!clustered.covers_cap(&local));
        ensure!(!clustered.covers_cap(&root));
        ensure!(root.covers_cap(&local));
        ensure!(root.covers_cap(&clustered));
        ensure!(root.covers("read", &p("path://phone/state/memory/x")?));
        ensure!(
            crate::grant::ResourceSelector::all()
                .matches("read", &p("path://phone/state/memory/x")?)
        );
        ensure!(
            CapSet(vec![local])
                .intersect(&CapSet(vec![phone]))
                .is_empty()
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
