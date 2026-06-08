//! Path: the universal addressing type.
//!
//! Form: `[cluster/]<scheme>/<seg>[/<seg>...]`
//!
//! The canonical wire form uses `scheme://segments` (e.g. `effect://inference/infer`).
//! Operation options live in structured input values, and attenuation
//! predicates live on capabilities.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
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
        serializer.serialize_str(&self.to_string())
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
    /// Segment contained an invalid character.
    #[error("invalid character in segment '{0}': only [a-zA-Z0-9][a-zA-Z0-9_.:-]* allowed")]
    BadSegmentChar(String),
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
        Ok(Self {
            cluster: None,
            scheme: SmolStr::from(scheme),
            segments: Vec::new(),
        })
    }

    /// Construct an empty path from a scheme.
    ///
    /// This debug-asserts that the scheme is valid; prefer [`Self::try_new`]
    /// for external input.
    pub fn new(scheme: impl Into<SmolStr>) -> Self {
        let s = scheme.into();
        debug_assert!(is_ident(&s), "scheme must be a valid identifier: {s}");
        Self {
            cluster: None,
            scheme: s,
            segments: Vec::new(),
        }
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
        let has_path_prefix = s.starts_with("path://");
        let stripped = s.strip_prefix("path://").unwrap_or(s);

        let (cluster, rest) = match has_path_prefix {
            true => match split_canonical_cluster(stripped) {
                Some((c, r)) => {
                    if !is_cluster_ident(c) {
                        return Err(PathError::BadClusterChar(c.into()));
                    }
                    (Some(SmolStr::from(c)), r)
                }
                None => (None, stripped),
            },
            false => (None, stripped),
        };
        let (scheme, body) = match rest.split_once("://") {
            Some((s, b)) => (s, b),
            None => match rest.split_once('/') {
                Some((s, b)) => (s, b),
                None => (rest, ""),
            },
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
        let mut segments = Vec::new();
        if !body.is_empty() {
            for seg in body.split('/') {
                if seg.is_empty() {
                    return Err(PathError::EmptySegment);
                }
                if !is_segment_ident(seg) {
                    return Err(PathError::BadSegmentChar(seg.into()));
                }
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
    /// Return the optional cluster.
    pub fn cluster(&self) -> Option<&str> {
        self.cluster.as_deref()
    }

    /// Append a segment without validation.
    pub fn push(mut self, seg: impl Into<SmolStr>) -> Self {
        self.segments.push(seg.into());
        self
    }

    /// Append one validated path segment without reparsing a complete path
    /// string. This rejects the same segment character set as [`Path::parse`].
    pub fn try_push(mut self, seg: impl AsRef<str>) -> Result<Self, PathError> {
        let seg = seg.as_ref();
        if seg.is_empty() {
            return Err(PathError::EmptySegment);
        }
        if !seg.is_ascii() {
            return Err(PathError::NonAscii);
        }
        if !is_segment_ident(seg) {
            return Err(PathError::BadSegmentChar(seg.into()));
        }
        self.segments.push(SmolStr::from(seg));
        Ok(self)
    }

    /// Attach a cluster without validation.
    pub fn with_cluster(mut self, c: impl Into<SmolStr>) -> Self {
        self.cluster = Some(c.into());
        self
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

    /// Clone this path for use as a path pattern.
    pub fn as_pattern(&self) -> Path {
        self.clone()
    }
}

// ── character-set helpers ──────────────────────────────────────────
//
// These are deliberately conservative. We intentionally forbid:
//  - non-ASCII (no Unicode confusables)
//  - most punctuation (only `_`, `-`, `.`, `:` allowed where noted)
//  - leading digits in scheme names

fn is_scheme_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_cluster_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_segment_ident(s: &str) -> bool {
    // Wildcard patterns are valid segments (for pattern-matching, not for
    // real target paths — PathValidators enforce the distinction).
    if s == "*" || s == "**" {
        return true;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ────────────────────────────────────────────────────────────────────

fn split_canonical_cluster(head: &str) -> Option<(&str, &str)> {
    let mut parts = head.split('/');
    let cluster = parts.next()?;
    let scheme = parts.next()?;
    // The current grammar is `path://[cluster/]<scheme>/<segment>...`.
    // Because cluster and scheme share the same character class, the parser
    // treats the first component as a cluster only when the next component is a
    // standard Nexus scheme. Otherwise `path://state/memory/alice` remains the
    // no-cluster form for `state://memory/alice`.
    if is_standard_scheme(scheme) && !is_standard_scheme(cluster) && parts.next().is_some() {
        Some((cluster, &head[cluster.len() + 1..]))
    } else {
        None
    }
}

fn is_standard_scheme(s: &str) -> bool {
    matches!(
        s,
        "state" | "effect" | "process" | "proc" | "mcp-res" | "blob" | "tensor"
    )
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

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(c) = &self.cluster {
            write!(f, "path://{}/{}", c, self.scheme)?;
        } else {
            write!(f, "{}://", self.scheme)?;
        }
        for (i, s) in self.segments.iter().enumerate() {
            if i > 0 || self.cluster.is_some() {
                f.write_str("/")?;
            }
            f.write_str(s)?;
        }
        Ok(())
    }
}

/// Convenience constructor used throughout the workspace and tests.
#[cfg(test)]
pub fn p(s: &str) -> Path {
    Path::parse(s).expect("invalid path literal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_effect_path() {
        let p = Path::parse("effect://inference/infer").unwrap();
        assert_eq!(p.scheme(), "effect");
        assert_eq!(
            p.segments(),
            &[SmolStr::from("inference"), SmolStr::from("infer")]
        );
        assert!(p.cluster().is_none());
    }

    #[test]
    fn parse_state_with_path_prefix() {
        let p = Path::parse("path://state/memory/alice/persona").unwrap();
        assert_eq!(p.scheme(), "state");
        assert_eq!(p.segments().len(), 3);
    }

    #[test]
    fn checked_builder_matches_parse_validation() {
        let path = Path::try_new("state")
            .unwrap()
            .try_push("kernel")
            .unwrap()
            .try_push("async")
            .unwrap()
            .try_push("42")
            .unwrap();
        assert_eq!(path.to_string(), "state://kernel/async/42");
        assert_eq!(
            Path::try_new("state")
                .unwrap()
                .try_push("bad/slash")
                .unwrap_err(),
            PathError::BadSegmentChar("bad/slash".into())
        );
    }

    #[test]
    fn path_params_are_rejected() {
        assert_eq!(
            Path::parse("effect://memory/recall@scope=user").unwrap_err(),
            PathError::ParamsUnsupported
        );
    }

    #[test]
    fn parse_cluster() {
        let p = Path::parse("path://pc-home/effect/memory/recall").unwrap();
        assert_eq!(p.cluster(), Some("pc-home"));
        assert_eq!(p.scheme(), "effect");
        assert_eq!(p.to_string(), "path://pc-home/effect/memory/recall");
    }

    #[test]
    fn noncanonical_cluster_spelling_is_rejected() {
        assert_eq!(
            Path::parse("path:////pc-home/effect/memory/recall").unwrap_err(),
            PathError::MissingScheme
        );
    }

    #[test]
    fn empty_segment_rejected() {
        assert_eq!(
            Path::parse("effect://a//b").unwrap_err(),
            PathError::EmptySegment
        );
    }

    #[test]
    fn missing_scheme_rejected() {
        assert_eq!(Path::parse("").unwrap_err(), PathError::Empty);
    }

    #[test]
    fn pattern_match_exact() {
        let p1 = p("effect://x/post");
        assert!(p1.matches(&p("effect://x/post")));
        assert!(!p1.matches(&p("effect://x/reply")));
    }

    #[test]
    fn pattern_match_single_wildcard() {
        let target = p("state://memory/alice/persona");
        assert!(target.matches(&p("state://memory/*/persona")));
        assert!(!target.matches(&p("state://memory/*")));
    }

    #[test]
    fn pattern_match_double_wildcard() {
        let target = p("state://memory/alice/episodic/2024/03/05");
        assert!(target.matches(&p("state://memory/alice/**")));
        assert!(target.matches(&p("state://memory/**")));
        assert!(target.matches(&p("state://**")));
    }

    #[test]
    fn pattern_match_requires_same_cluster() {
        let target = p("path://pc-home/state/memory/alice");
        assert!(target.matches(&p("path://pc-home/state/memory/*")));
        assert!(!target.matches(&p("state://memory/*")));
        assert!(!target.matches(&p("path://phone/state/memory/*")));
    }

    #[test]
    fn prefix_check() {
        let parent = p("process://alice");
        let child = p("process://alice/x-bot");
        assert!(parent.is_prefix_of(&child));
        assert!(!child.is_prefix_of(&parent));
    }

    #[test]
    fn prefix_check_requires_same_cluster() {
        let parent = p("path://pc-home/process/alice");
        let child = p("path://pc-home/process/alice/x-bot");
        let other_cluster = p("path://phone/process/alice/x-bot");
        assert!(parent.is_prefix_of(&child));
        assert!(!parent.is_prefix_of(&other_cluster));
    }

    #[test]
    fn round_trip_display() {
        let s = "effect://inference/infer";
        let path = Path::parse(s).unwrap();
        assert_eq!(path.to_string(), s);
    }

    #[test]
    fn serialize_roundtrip() {
        let path = p("state://memory/alice/persona");
        let s = serde_json::to_string(&path).unwrap();
        let back: Path = serde_json::from_str(&s).unwrap();
        assert_eq!(path, back);
    }
}
