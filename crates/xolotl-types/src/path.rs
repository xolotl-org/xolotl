//! Path: the universal addressing type.
//!
//! Form: `<scheme>://<segments>` locally, or
//! `path://<cluster>/<scheme>/<segments>` for a clustered target.
//!
//! The canonical wire form uses `scheme://segments` (e.g. `effect://inference/infer`).
//! Operation options live in structured input values, and attenuation
//! predicates live on capabilities.

use alloc::{string::String, vec::Vec};
use core::fmt;
use core::hash::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;

pub(crate) mod identifier;
mod namespace;
pub use namespace::{
    BOOTSTRAP_PHASE_PATH, FACT_PREFIX, KERNEL_RESERVED_PREFIXES, QUARANTINE_PREFIX, STREAM_PREFIX,
    VAULT_PREFIX, is_fact_reserved, is_kernel_reserved, is_vault_reserved,
};

/// A parsed path. Internally stored normalized: scheme + segments + optional
/// cluster.
#[derive(Clone, Debug)]
pub struct Path {
    cluster: Option<SmolStr>,
    scheme: SmolStr,
    segments: Vec<SmolStr>,
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.cluster == other.cluster
            && self.scheme == other.scheme
            && self.segments == other.segments
    }
}

impl Eq for Path {}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cluster
            .cmp(&other.cluster)
            .then_with(|| self.scheme.cmp(&other.scheme))
            .then_with(|| self.segments.cmp(&other.segments))
    }
}

impl Hash for Path {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cluster.hash(state);
        self.scheme.hash(state);
        self.segments.hash(state);
    }
}

impl Serialize for Path {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Path {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Path::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Path parsing and validation errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    /// Path string was empty.
    #[error("empty path")]
    Empty,
    /// Path had no scheme.
    #[error("missing scheme")]
    MissingScheme,
    /// Local path omitted the `://` separator after its scheme.
    #[error("path must include '://' after the scheme")]
    MissingSeparator,
    /// Scheme contained `/`.
    #[error("scheme cannot contain '/'")]
    BadScheme,
    /// A segment was empty.
    #[error("segment cannot be empty")]
    EmptySegment,
    /// Inline path parameters are not supported.
    #[error("path parameters are not supported; put options in operation input values")]
    ParamsUnsupported,
    /// Scheme contained an invalid character.
    #[error("invalid character in scheme '{0}': only [a-zA-Z][a-zA-Z0-9_-]* allowed")]
    BadSchemeChar(String),
    /// `path` is the marker for a clustered path, not a resource scheme.
    #[error("scheme 'path' is reserved for clustered paths")]
    ReservedScheme,
    /// Segment contained an invalid character.
    #[error("invalid character in segment '{0}': only [a-zA-Z0-9][a-zA-Z0-9_.:-]* allowed")]
    BadSegmentChar(String),
    /// A concrete path segment used wildcard syntax.
    #[error("wildcard segment '{0}' is only valid in path patterns")]
    WildcardSegment(String),
    /// Cluster contained an invalid character.
    #[error("invalid character in cluster '{0}': only [a-zA-Z0-9_-]+ allowed")]
    BadClusterChar(String),
    /// Path contained non-ASCII characters.
    #[error("non-ASCII characters are not allowed in paths")]
    NonAscii,
}

impl Path {
    /// Construct an empty path from a validated scheme without parsing a full
    /// path string. Use this for generated/internal paths whose segments are
    /// already structured data.
    pub fn try_new(scheme: impl AsRef<str>) -> Result<Self, PathError> {
        let scheme = scheme.as_ref();
        if scheme.is_empty() {
            return Err(PathError::MissingScheme);
        }
        if !scheme.is_ascii() {
            return Err(PathError::NonAscii);
        }
        if scheme.contains('/') {
            return Err(PathError::BadScheme);
        }
        if !is_scheme_ident(scheme) {
            return Err(PathError::BadSchemeChar(scheme.into()));
        }
        if scheme == "path" {
            return Err(PathError::ReservedScheme);
        }
        Ok(Self {
            cluster: None,
            scheme: SmolStr::from(scheme),
            segments: Vec::new(),
        })
    }

    /// Parse a path string.
    pub fn parse(s: &str) -> Result<Self, PathError> {
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        // Reject non-ASCII early — paths are ASCII-only.
        if !s.is_ascii() {
            return Err(PathError::NonAscii);
        }
        if s.contains('@') {
            return Err(PathError::ParamsUnsupported);
        }
        let (cluster, scheme, body) = if let Some(clustered) = s.strip_prefix("path://") {
            let (cluster, rest) = clustered.split_once('/').ok_or(PathError::MissingScheme)?;
            validate_cluster_ident(cluster)?;
            let (scheme, body) = rest.split_once('/').unwrap_or((rest, ""));
            if rest.ends_with('/') {
                return Err(PathError::EmptySegment);
            }
            (Some(SmolStr::from(cluster)), scheme, body)
        } else {
            let (scheme, body) = s.split_once("://").ok_or(PathError::MissingSeparator)?;
            (None, scheme, body)
        };
        if scheme.is_empty() {
            return Err(PathError::MissingScheme);
        }
        if scheme.contains('/') {
            return Err(PathError::BadScheme);
        }
        if !is_scheme_ident(scheme) {
            return Err(PathError::BadSchemeChar(scheme.into()));
        }
        if scheme == "path" {
            return Err(PathError::ReservedScheme);
        }
        let mut segments = Vec::new();
        if !body.is_empty() {
            for seg in body.split('/') {
                validate_segment(seg)?;
                segments.push(SmolStr::from(seg));
            }
        }
        Ok(Self {
            cluster,
            scheme: SmolStr::from(scheme),
            segments,
        })
    }

    /// Return the path scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    /// Return path segments.
    pub fn segments(&self) -> &[SmolStr] {
        &self.segments
    }
    /// Remove the final segment in place. Returns `false` when this path is
    /// already at its scheme root; the scheme and cluster are preserved.
    pub fn pop_segment(&mut self) -> bool {
        self.segments.pop().is_some()
    }
    /// Return the optional cluster.
    pub fn cluster(&self) -> Option<&str> {
        self.cluster.as_deref()
    }

    /// Number of bytes in the canonical path text without formatting it.
    /// Returns `None` if the total cannot fit in `usize`.
    pub fn canonical_len(&self) -> Option<usize> {
        self.canonical_parts()
            .try_fold(0usize, |bytes, part| bytes.checked_add(part.len()))
    }

    /// Append one validated path segment without reparsing a complete path
    /// string. This rejects the same segment character set as [`Path::parse`].
    pub fn try_push(mut self, seg: impl AsRef<str>) -> Result<Self, PathError> {
        let seg = seg.as_ref();
        validate_segment(seg)?;
        self.segments.push(SmolStr::from(seg));
        Ok(self)
    }

    /// Move a validated segment into an already owned path without copying
    /// its text. Used by the event builder after its incremental validator has
    /// accepted the segment.
    pub(crate) fn try_push_owned(mut self, segment: SmolStr) -> Result<Self, PathError> {
        validate_segment(&segment)?;
        self.segments.push(segment);
        Ok(self)
    }

    /// Append one validated concrete path segment. Unlike [`Self::try_push`],
    /// this rejects `*` and `**`, so it is appropriate for persisted keys,
    /// resource names, and other non-pattern paths built from caller data.
    pub fn try_push_literal(self, seg: impl AsRef<str>) -> Result<Self, PathError> {
        let seg = seg.as_ref();
        if is_wildcard_segment(seg) {
            return Err(PathError::WildcardSegment(seg.into()));
        }
        self.try_push(seg)
    }

    /// Attach a validated cluster. Use this for external input.
    pub fn try_with_cluster(mut self, c: impl AsRef<str>) -> Result<Self, PathError> {
        let c = c.as_ref();
        validate_cluster_ident(c)?;
        self.cluster = Some(SmolStr::from(c));
        Ok(self)
    }

    /// True if `pattern` matches `self`. Patterns may use `*` as a single
    /// segment wildcard, `**` as a multi-segment wildcard.
    pub fn matches(&self, pattern: &Path) -> bool {
        if pattern.cluster != self.cluster {
            return false;
        }
        if pattern.scheme != self.scheme {
            return false;
        }
        match_segments(&pattern.segments, &self.segments)
    }

    /// True if `self` is a prefix of `other` (same scheme, all of `self`'s
    /// segments equal the first segments of `other`).
    pub fn is_prefix_of(&self, other: &Path) -> bool {
        if self.cluster != other.cluster {
            return false;
        }
        if self.scheme != other.scheme {
            return false;
        }
        if self.segments.len() > other.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(other.segments.iter())
            .all(|(a, b)| a == b)
    }

    /// True when no segment uses path-pattern wildcard syntax.
    pub fn is_concrete(&self) -> bool {
        self.segments
            .iter()
            .all(|segment| !is_wildcard_segment(segment.as_str()))
    }

    /// Clone this path for use as a path pattern.
    pub fn as_pattern(&self) -> Path {
        self.clone()
    }
}

// Path syntax accepts a narrow ASCII set so validation stays predictable.

fn is_scheme_ident(s: &str) -> bool {
    identifier::validate(s.as_bytes(), identifier::IdentifierKind::Scheme).is_ok()
}

fn is_cluster_ident(s: &str) -> bool {
    identifier::validate(s.as_bytes(), identifier::IdentifierKind::Cluster).is_ok()
}

fn validate_cluster_ident(s: &str) -> Result<(), PathError> {
    if !s.is_ascii() {
        return Err(PathError::NonAscii);
    }
    if !is_cluster_ident(s) {
        return Err(PathError::BadClusterChar(s.into()));
    }
    Ok(())
}

fn is_segment_ident(s: &str) -> bool {
    identifier::validate(s.as_bytes(), identifier::IdentifierKind::Segment).is_ok()
}

/// A single unqualified ID used for installations, projections, models, and
/// other named entries within a State path. This is narrower than a general
/// path segment, which may contain `.` or `:`.
pub fn is_simple_id_segment(id: &str) -> bool {
    let mut bytes = id.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_segment(segment: &str) -> Result<(), PathError> {
    if segment.is_empty() {
        return Err(PathError::EmptySegment);
    }
    if !segment.is_ascii() {
        return Err(PathError::NonAscii);
    }
    if !is_segment_ident(segment) {
        return Err(PathError::BadSegmentChar(segment.into()));
    }
    Ok(())
}

fn is_wildcard_segment(s: &str) -> bool {
    matches!(s, "*" | "**")
}

pub(crate) fn match_segments(pat: &[SmolStr], seg: &[SmolStr]) -> bool {
    match_segment_tokens(pat, seg, |pattern, target| {
        pattern == "*" || pattern == target
    })
}

/// Conservative structural coverage check for two wildcard patterns. A
/// single-segment `*` cannot consume a child `**`, which can represent zero
/// or many segments. This may reject valid inclusion; it must never widen a
/// delegated capability.
pub(crate) fn pattern_subsumes_segments(parent: &[SmolStr], child: &[SmolStr]) -> bool {
    match_segment_tokens(parent, child, |pattern, target| {
        pattern == target || (pattern == "*" && target != "**")
    })
}

fn match_segment_tokens(
    pat: &[SmolStr],
    seg: &[SmolStr],
    single_segment_covers: impl Fn(&str, &str) -> bool,
) -> bool {
    let mut pi = 0usize;
    let mut si = 0usize;
    // The latest `**` can absorb any later mismatch. Backtracking to an
    // earlier one cannot add a match: it would only move the latest `**`
    // further right, reducing the suffix it may consume. Keeping one retry
    // position avoids recursive, potentially exponential matching and uses
    // no allocation on the authorization path.
    let mut globstar = None;
    let mut retry_si = 0usize;
    while si < seg.len() {
        if pi < pat.len() {
            if pat[pi].as_str() == "**" {
                globstar = Some(pi);
                retry_si = si;
                pi += 1;
                continue;
            }
            if single_segment_covers(pat[pi].as_str(), seg[si].as_str()) {
                pi += 1;
                si += 1;
                continue;
            }
        }
        let Some(star_pi) = globstar else {
            return false;
        };
        retry_si += 1;
        si = retry_si;
        pi = star_pi + 1;
    }
    while pi < pat.len() && pat[pi].as_str() == "**" {
        pi += 1;
    }
    pi == pat.len()
}

/// Borrow the canonical text without assembling a temporary path string.
pub(crate) struct CanonicalParts<'a> {
    path: &'a Path,
    prefix: u8,
    segments: core::slice::Iter<'a, SmolStr>,
    separator: bool,
    pending: Option<&'a str>,
}

impl Path {
    pub(crate) fn canonical_parts(&self) -> CanonicalParts<'_> {
        CanonicalParts {
            path: self,
            prefix: 0,
            segments: self.segments.iter(),
            separator: self.cluster.is_some(),
            pending: None,
        }
    }
}

impl<'a> Iterator for CanonicalParts<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix = match (self.path.cluster(), self.prefix) {
            (Some(_), 0) => Some("path://"),
            (Some(cluster), 1) => Some(cluster),
            (Some(_), 2) => Some("/"),
            (Some(_), 3) | (None, 0) => Some(self.path.scheme()),
            (None, 1) => Some("://"),
            _ => None,
        };
        if let Some(prefix) = prefix {
            self.prefix += 1;
            return Some(prefix);
        }
        if let Some(segment) = self.pending.take() {
            return Some(segment);
        }
        let segment = self.segments.next()?.as_str();
        if self.separator {
            self.pending = Some(segment);
            Some("/")
        } else {
            self.separator = true;
            Some(segment)
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in self.canonical_parts() {
            f.write_str(part)?;
        }
        Ok(())
    }
}

/// Convenience constructor used throughout the workspace and tests.
#[cfg(test)]
pub fn p(s: &str) -> anyhow::Result<Path> {
    Ok(Path::parse(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use anyhow::{Context, bail, ensure};

    #[test]
    fn simple_ids_are_safe_for_named_state_entries() -> anyhow::Result<()> {
        for id in ["bridge", "model_2", "source-7"] {
            ensure!(is_simple_id_segment(id));
            Path::try_new("state")?.try_push_literal(id)?;
        }
        for id in ["", "_hidden", "-hidden", "a.b", "a/b", "é", "*"] {
            ensure!(!is_simple_id_segment(id), "accepted {id:?}");
        }
        Ok(())
    }

    #[test]
    fn parse_effect_path() -> anyhow::Result<()> {
        let p = Path::parse("effect://inference/infer")?;
        ensure!(p.scheme() == "effect", "unexpected scheme: {}", p.scheme());
        ensure!(
            p.segments() == [SmolStr::from("inference"), SmolStr::from("infer")],
            "unexpected segments: {:?}",
            p.segments()
        );
        ensure!(
            p.cluster().is_none(),
            "unexpected cluster: {:?}",
            p.cluster()
        );
        Ok(())
    }

    #[test]
    fn clustered_marker_requires_an_explicit_cluster() -> anyhow::Result<()> {
        let err = match Path::parse("path://state") {
            Ok(path) => bail!("clustered path without scheme parsed: {path}"),
            Err(error) => error,
        };
        ensure!(err == PathError::MissingScheme);
        let p = Path::parse("state://memory/alice/persona")?;
        ensure!(p.scheme() == "state", "unexpected scheme: {}", p.scheme());
        ensure!(
            p.segments().len() == 3,
            "unexpected segment count: {}",
            p.segments().len()
        );
        Ok(())
    }

    #[test]
    fn path_literals_require_an_explicit_scheme_separator() {
        for shorthand in ["effect", "effect/jobs/first", "remote/effect/jobs/first"] {
            assert_eq!(Path::parse(shorthand), Err(PathError::MissingSeparator));
        }
        assert_eq!(
            Path::parse("path://remote/effect/"),
            Err(PathError::EmptySegment)
        );
    }

    #[test]
    fn clustered_custom_scheme_roundtrips_without_guessing() -> anyhow::Result<()> {
        let path = Path::try_new("custom")?
            .try_with_cluster("phone")?
            .try_push_literal("resource")?;
        let text = path.to_string();
        ensure!(text == "path://phone/custom/resource");
        ensure!(Path::parse(&text)? == path);

        let root = Path::try_new("custom")?.try_with_cluster("phone")?;
        ensure!(Path::parse(&root.to_string())? == root);
        ensure!(Path::try_new("path") == Err(PathError::ReservedScheme));
        Ok(())
    }

    #[test]
    fn pop_segment_preserves_local_and_clustered_roots() -> anyhow::Result<()> {
        for (source, parent, root) in [
            ("state://memory/item", "state://memory", "state://"),
            (
                "path://phone/state/memory/item",
                "path://phone/state/memory",
                "path://phone/state",
            ),
        ] {
            let mut path = Path::parse(source)?;
            ensure!(path.pop_segment());
            ensure!(path == Path::parse(parent)?);
            ensure!(path.pop_segment());
            ensure!(path == Path::parse(root)?);
            ensure!(!path.pop_segment());
            ensure!(path == Path::parse(root)?);
        }
        Ok(())
    }

    #[test]
    fn checked_builder_matches_parse_validation() -> anyhow::Result<()> {
        let path = Path::try_new("state")
            .context("build state path")?
            .try_push("kernel")
            .context("push kernel")?
            .try_push("async")
            .context("push async")?
            .try_push("42")
            .context("push id")?;
        ensure!(
            path.to_string() == "state://kernel/async/42",
            "unexpected path: {path}"
        );
        let err = match Path::try_new("state")?.try_push("bad/slash") {
            Ok(path) => bail!("bad segment was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::BadSegmentChar("bad/slash".into()),
            "unexpected bad segment error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn literal_builder_rejects_pattern_wildcards() -> anyhow::Result<()> {
        let pattern = Path::try_new("state")?.try_push("**")?;
        ensure!(
            !pattern.is_concrete(),
            "wildcard path was treated as concrete"
        );
        let err = match Path::try_new("state")?.try_push_literal("**") {
            Ok(path) => bail!("wildcard literal segment was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::WildcardSegment("**".into()),
            "unexpected wildcard literal error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn checked_builder_validates_cluster() -> anyhow::Result<()> {
        let path = Path::try_new("effect")?
            .try_with_cluster("pc-home")?
            .try_push("memory")?;
        ensure!(
            path.cluster() == Some("pc-home"),
            "unexpected cluster: {:?}",
            path.cluster()
        );
        let bad_cluster = match Path::try_new("effect")?.try_with_cluster("bad/slash") {
            Ok(path) => bail!("bad cluster was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            bad_cluster == PathError::BadClusterChar("bad/slash".into()),
            "unexpected bad cluster error: {bad_cluster:?}"
        );
        let scheme_named_cluster = Path::try_new("effect")?.try_with_cluster("state")?;
        ensure!(
            Path::parse(&scheme_named_cluster.to_string())? == scheme_named_cluster,
            "scheme-named cluster did not round-trip"
        );
        Ok(())
    }

    #[test]
    fn path_params_are_rejected() -> anyhow::Result<()> {
        let err = match Path::parse("effect://memory/recall@scope=user") {
            Ok(path) => bail!("path parameters were accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::ParamsUnsupported,
            "unexpected params error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn parse_cluster() -> anyhow::Result<()> {
        let p = Path::parse("path://pc-home/effect/memory/recall")?;
        ensure!(
            p.cluster() == Some("pc-home"),
            "unexpected cluster: {:?}",
            p.cluster()
        );
        ensure!(p.scheme() == "effect", "unexpected scheme: {}", p.scheme());
        ensure!(
            p.to_string() == "path://pc-home/effect/memory/recall",
            "unexpected path: {p}"
        );
        Ok(())
    }

    #[test]
    fn noncanonical_cluster_spelling_is_rejected() -> anyhow::Result<()> {
        let err = match Path::parse("path:////pc-home/effect/memory/recall") {
            Ok(path) => bail!("noncanonical cluster was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::BadClusterChar(String::new()),
            "unexpected cluster spelling error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn empty_segment_rejected() -> anyhow::Result<()> {
        let err = match Path::parse("effect://a//b") {
            Ok(path) => bail!("empty segment was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::EmptySegment,
            "unexpected empty segment error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn missing_scheme_rejected() -> anyhow::Result<()> {
        let err = match Path::parse("") {
            Ok(path) => bail!("empty path was accepted: {path}"),
            Err(error) => error,
        };
        ensure!(
            err == PathError::Empty,
            "unexpected empty path error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn pattern_match_exact() -> anyhow::Result<()> {
        let p1 = p("effect://x/post")?;
        ensure!(
            p1.matches(&p("effect://x/post")?),
            "exact pattern did not match"
        );
        ensure!(
            !p1.matches(&p("effect://x/reply")?),
            "sibling path matched exact pattern"
        );
        Ok(())
    }

    #[test]
    fn pattern_match_single_wildcard() -> anyhow::Result<()> {
        let target = p("state://memory/alice/persona")?;
        ensure!(
            target.matches(&p("state://memory/*/persona")?),
            "single wildcard did not match"
        );
        ensure!(
            !target.matches(&p("state://memory/*")?),
            "single wildcard matched too many segments"
        );
        Ok(())
    }

    #[test]
    fn pattern_match_double_wildcard() -> anyhow::Result<()> {
        let target = p("state://memory/alice/episodic/2024/03/05")?;
        ensure!(
            target.matches(&p("state://memory/alice/**")?),
            "owner wildcard failed"
        );
        ensure!(
            target.matches(&p("state://memory/**")?),
            "memory wildcard failed"
        );
        ensure!(target.matches(&p("state://**")?), "scheme wildcard failed");
        Ok(())
    }

    #[test]
    fn iterative_match_agrees_with_recursive_glob_semantics() -> anyhow::Result<()> {
        fn original(pat: &[SmolStr], seg: &[SmolStr]) -> bool {
            let Some((head, tail)) = pat.split_first() else {
                return seg.is_empty();
            };
            if head == "**" {
                return (0..=seg.len()).any(|consumed| original(tail, &seg[consumed..]));
            }
            let Some((first, rest)) = seg.split_first() else {
                return false;
            };
            (head == "*" || head == first) && original(tail, rest)
        }

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

        let patterns = sequences(&["a", "b", "*", "**"], 5);
        let targets = sequences(&["a", "b"], 6);
        for pattern in &patterns {
            for target in &targets {
                ensure!(
                    match_segments(pattern, target) == original(pattern, target),
                    "glob mismatch: pattern={pattern:?}, target={target:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn many_globstars_do_not_require_recursive_stack() -> anyhow::Result<()> {
        let mut pattern = Vec::new();
        let mut target = Vec::new();
        for _ in 0..256 {
            pattern.push(SmolStr::from("**"));
            pattern.push(SmolStr::from("a"));
            target.push(SmolStr::from("a"));
        }
        ensure!(match_segments(&pattern, &target));
        pattern.push(SmolStr::from("b"));
        ensure!(!match_segments(&pattern, &target));
        Ok(())
    }

    #[test]
    fn pattern_match_requires_same_cluster() -> anyhow::Result<()> {
        let target = p("path://pc-home/state/memory/alice")?;
        ensure!(
            target.matches(&p("path://pc-home/state/memory/*")?),
            "same-cluster pattern did not match"
        );
        ensure!(
            !target.matches(&p("state://memory/*")?),
            "unclustered pattern matched clustered path"
        );
        ensure!(
            !target.matches(&p("path://phone/state/memory/*")?),
            "different cluster matched"
        );
        Ok(())
    }

    #[test]
    fn prefix_check() -> anyhow::Result<()> {
        let parent = p("process://alice")?;
        let child = p("process://alice/x-bot")?;
        ensure!(
            parent.is_prefix_of(&child),
            "parent was not prefix of child"
        );
        ensure!(!child.is_prefix_of(&parent), "child was prefix of parent");
        Ok(())
    }

    #[test]
    fn prefix_check_requires_same_cluster() -> anyhow::Result<()> {
        let parent = p("path://pc-home/process/alice")?;
        let child = p("path://pc-home/process/alice/x-bot")?;
        let other_cluster = p("path://phone/process/alice/x-bot")?;
        ensure!(
            parent.is_prefix_of(&child),
            "same-cluster parent was not prefix"
        );
        ensure!(
            !parent.is_prefix_of(&other_cluster),
            "different-cluster child matched prefix"
        );
        Ok(())
    }

    #[test]
    fn round_trip_display() -> anyhow::Result<()> {
        let s = "effect://inference/infer";
        let path = Path::parse(s)?;
        ensure!(path.to_string() == s, "display roundtrip failed: {path}");
        Ok(())
    }

    #[test]
    fn canonical_len_matches_local_and_clustered_display() -> anyhow::Result<()> {
        for source in [
            "state://",
            "state://application/item",
            "path://cluster/state",
            "path://cluster/state/application/item",
        ] {
            let path = Path::parse(source)?;
            ensure!(path.canonical_len() == Some(path.to_string().len()));
        }
        Ok(())
    }

    #[test]
    fn serialize_roundtrip() -> anyhow::Result<()> {
        let path = p("state://memory/alice/persona")?;
        let s = serde_json::to_string(&path)?;
        let back: Path = serde_json::from_str(&s)?;
        ensure!(path == back, "serde roundtrip changed path");
        Ok(())
    }
}
