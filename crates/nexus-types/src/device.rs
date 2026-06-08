//! Unified EffectProvider model.
//!
//! Every source of Effects in Nexus — local tools (fs, terminal, fetch),
//! remote devices, MCP servers, plugins, bridges — is an EffectProvider.
//! They differ only in transport, trust level, and namespace policy.

use crate::replay::Purity;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A provider of one or more Effects to the Nexus kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectProvider {
    /// Stable provider id.
    pub id: String,
    /// Human-readable provider name.
    pub display_name: String,
    /// Transport used to reach the provider.
    pub transport: Transport,
    /// Trust level assigned to the provider.
    pub trust: TrustLevel,
    /// Effects this provider can handle.
    pub capabilities: Vec<EffectCapability>,
    /// Current provider lifecycle status.
    #[serde(default)]
    pub status: ProviderStatus,
}

/// How the kernel communicates with this provider.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// In-process provider.
    #[default]
    InProcess,
    /// gRPC provider endpoint.
    Grpc {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
    /// Stdio child process provider.
    Stdio {
        /// Optional executable command.
        command: Option<String>,
        /// Command arguments.
        args: Vec<String>,
    },
    /// WebSocket provider endpoint.
    WebSocket {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
    /// HTTP provider endpoint.
    Http {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
}

/// Trust determines namespace policy and sandboxing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Full trust — can register any Effect path (local tools, remote devices).
    #[default]
    Full,
    /// Sandboxed — must register under `effect://plugin/{id}/*` or `effect://mcp-tool/{id}/*`.
    Sandboxed,
}

/// A single Effect this provider can handle. Carries enough metadata
/// for modality-aware routing and schema-versioned wire contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectCapability {
    /// Effect resource path this capability handles.
    pub effect_path: String,
    /// Declared purity for replay classification.
    pub purity: Purity,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional input schema descriptor.
    #[serde(default)]
    pub input_schema: Option<Value>,
    /// Output schema — lets the router validate / project the result.
    #[serde(default)]
    pub output_schema: Option<Value>,
    /// Modalities this effect accepts/produces, for
    /// modality-aware routing. `None` = text-only by default.
    #[serde(default)]
    pub modality: Option<crate::resource::ModalitySet>,
    /// Wire schema version, bumped on a breaking I/O change.
    #[serde(default)]
    pub schema_version: u32,
}

/// Provider lifecycle status.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    /// Provider has been registered but not started.
    #[default]
    Registered,
    /// Provider startup is in progress.
    Starting,
    /// Provider is reachable.
    Online,
    /// Provider is not reachable.
    Offline,
    /// Provider reported an error.
    Error(
        /// Error message.
        String,
    ),
}

impl EffectProvider {
    /// Create a local (in-process, full-trust) provider.
    pub fn local(display_name: impl Into<String>, capabilities: Vec<EffectCapability>) -> Self {
        Self {
            id: "local".into(),
            display_name: display_name.into(),
            transport: Transport::InProcess,
            trust: TrustLevel::Full,
            capabilities,
            status: ProviderStatus::Online,
        }
    }

    /// Convert this provider descriptor to a Nexus value map.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("id".into(), Value::Str(self.id.clone()));
        m.insert("display_name".into(), Value::Str(self.display_name.clone()));
        m.insert("transport".into(), transport_to_value(&self.transport));
        m.insert("trust".into(), Value::Str(trust_to_str(self.trust).into()));
        let caps: Vec<Value> = self.capabilities.iter().map(|c| c.to_value()).collect();
        m.insert("capabilities".into(), Value::List(caps));
        m.insert("status".into(), Value::Str(status_to_str(&self.status)));
        Value::Map(m)
    }

    /// Decode a provider descriptor from a Nexus value map.
    pub fn from_value(v: &Value) -> Option<Self> {
        let m = v.as_map()?;
        let id = m.get("id")?.as_str()?.to_string();
        let display_name = m.get("display_name")?.as_str()?.to_string();
        let transport = match m.get("transport") {
            Some(v) => transport_from_value(v)?,
            None => Transport::default(),
        };
        let trust = match m.get("trust").and_then(|v| v.as_str()) {
            Some("sandboxed") => TrustLevel::Sandboxed,
            Some("full") | None => TrustLevel::Full,
            Some(_) => return None,
        };
        let caps = match m.get("capabilities") {
            Some(Value::List(list)) => {
                let mut caps = Vec::with_capacity(list.len());
                for cap in list {
                    caps.push(EffectCapability::from_value(cap)?);
                }
                caps
            }
            Some(_) => return None,
            _ => vec![],
        };
        let status = match m.get("status") {
            Some(v) => status_from_value(v)?,
            None => ProviderStatus::default(),
        };
        Some(Self {
            id,
            display_name,
            transport,
            trust,
            capabilities: caps,
            status,
        })
    }
}

impl EffectCapability {
    /// Create a capability descriptor for one effect path.
    pub fn new(effect_path: impl Into<String>, purity: Purity) -> Self {
        Self {
            effect_path: effect_path.into(),
            purity,
            description: None,
            input_schema: None,
            output_schema: None,
            modality: None,
            schema_version: 0,
        }
    }

    /// Convert this capability descriptor to a Nexus value map.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("effect_path".into(), Value::Str(self.effect_path.clone()));
        m.insert(
            "purity".into(),
            Value::Str(format!("{:?}", self.purity).to_lowercase()),
        );
        if let Some(desc) = &self.description {
            m.insert("description".into(), Value::Str(desc.clone()));
        }
        if let Some(schema) = &self.input_schema {
            m.insert("input_schema".into(), schema.clone());
        }
        if let Some(schema) = &self.output_schema {
            m.insert("output_schema".into(), schema.clone());
        }
        if let Some(modality) = self.modality {
            m.insert("modality".into(), Value::Int(modality.bits() as i64));
        }
        if self.schema_version != 0 {
            m.insert(
                "schema_version".into(),
                Value::Int(self.schema_version as i64),
            );
        }
        Value::Map(m)
    }

    /// Decode a capability descriptor from a Nexus value map.
    pub fn from_value(v: &Value) -> Option<Self> {
        let m = v.as_map()?;
        let effect_path = m.get("effect_path")?.as_str()?.to_string();
        let purity = match m.get("purity").and_then(|v| v.as_str()) {
            Some("pure") => Purity::Pure,
            Some("idempotent") => Purity::Idempotent,
            Some("effectful") | None => Purity::Effectful,
            Some(_) => return None,
        };
        let description = m
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let input_schema = m.get("input_schema").cloned();
        let output_schema = m.get("output_schema").cloned();
        let modality = m.get("modality").and_then(|v| v.as_int()).and_then(|bits| {
            (bits >= 0).then(|| crate::resource::ModalitySet::from_bits_retain(bits as u16))
        });
        let schema_version = match m.get("schema_version").and_then(|v| v.as_int()) {
            Some(v) if v < 0 => return None,
            Some(v) => v as u32,
            None => 0,
        };
        Some(Self {
            effect_path,
            purity,
            description,
            input_schema,
            output_schema,
            modality,
            schema_version,
        })
    }
}

fn transport_to_value(t: &Transport) -> Value {
    match t {
        Transport::InProcess => Value::Str("in_process".into()),
        Transport::Grpc { endpoint } => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("grpc".into()));
            if let Some(ep) = endpoint {
                m.insert("endpoint".into(), Value::Str(ep.clone()));
            }
            Value::Map(m)
        }
        Transport::Stdio { command, args } => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("stdio".into()));
            if let Some(cmd) = command {
                m.insert("command".into(), Value::Str(cmd.clone()));
            }
            if !args.is_empty() {
                m.insert(
                    "args".into(),
                    Value::List(args.iter().map(|a| Value::Str(a.clone())).collect()),
                );
            }
            Value::Map(m)
        }
        Transport::WebSocket { endpoint } => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("websocket".into()));
            if let Some(ep) = endpoint {
                m.insert("endpoint".into(), Value::Str(ep.clone()));
            }
            Value::Map(m)
        }
        Transport::Http { endpoint } => {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Value::Str("http".into()));
            if let Some(ep) = endpoint {
                m.insert("endpoint".into(), Value::Str(ep.clone()));
            }
            Value::Map(m)
        }
    }
}

fn transport_from_value(v: &Value) -> Option<Transport> {
    match v {
        Value::Str(s) if s == "in_process" => Some(Transport::InProcess),
        Value::Map(m) => {
            let kind = m
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("in_process");
            let endpoint = m.get("endpoint").and_then(|v| v.as_str()).map(String::from);
            match kind {
                "grpc" => Some(Transport::Grpc { endpoint }),
                "stdio" => {
                    let command = m.get("command").and_then(|v| v.as_str()).map(String::from);
                    let args = match m.get("args") {
                        Some(Value::List(l)) => l
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect(),
                        Some(_) => return None,
                        None => vec![],
                    };
                    Some(Transport::Stdio { command, args })
                }
                "websocket" => Some(Transport::WebSocket { endpoint }),
                "http" => Some(Transport::Http { endpoint }),
                "in_process" => Some(Transport::InProcess),
                _ => None,
            }
        }
        _ => None,
    }
}

fn trust_to_str(t: TrustLevel) -> &'static str {
    match t {
        TrustLevel::Full => "full",
        TrustLevel::Sandboxed => "sandboxed",
    }
}

fn status_to_str(s: &ProviderStatus) -> String {
    match s {
        ProviderStatus::Registered => "registered".into(),
        ProviderStatus::Starting => "starting".into(),
        ProviderStatus::Online => "online".into(),
        ProviderStatus::Offline => "offline".into(),
        ProviderStatus::Error(e) => format!("error:{}", e),
    }
}

fn status_from_value(v: &Value) -> Option<ProviderStatus> {
    match v.as_str() {
        Some("registered") => Some(ProviderStatus::Registered),
        Some("starting") => Some(ProviderStatus::Starting),
        Some("online") => Some(ProviderStatus::Online),
        Some("offline") => Some(ProviderStatus::Offline),
        Some(s) if s.starts_with("error:") => Some(ProviderStatus::Error(s[6..].into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_roundtrip() {
        let mut read = EffectCapability::new("effect://fs/read", Purity::Idempotent);
        read.input_schema = Some(Value::Map(BTreeMap::from([(
            "type".into(),
            Value::Str("object".into()),
        )])));
        read.output_schema = Some(Value::Map(BTreeMap::from([(
            "type".into(),
            Value::Str("string".into()),
        )])));
        read.modality =
            Some(crate::resource::ModalitySet::TEXT | crate::resource::ModalitySet::IMAGE);
        read.schema_version = 2;
        let p = EffectProvider {
            id: "phone".into(),
            display_name: "Alice's Phone".into(),
            transport: Transport::Grpc {
                endpoint: Some("192.168.1.5:9090".into()),
            },
            trust: TrustLevel::Full,
            capabilities: vec![
                read,
                EffectCapability::new("effect://fetch/get", Purity::Effectful),
            ],
            status: ProviderStatus::Online,
        };
        let v = p.to_value();
        let back = EffectProvider::from_value(&v).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn local_constructor() {
        let p = EffectProvider::local("my-pc", vec![]);
        assert_eq!(p.id, "local");
        assert_eq!(p.transport, Transport::InProcess);
        assert_eq!(p.trust, TrustLevel::Full);
        assert_eq!(p.status, ProviderStatus::Online);
    }

    #[test]
    fn sandboxed_provider() {
        let p = EffectProvider {
            id: "mcp-github".into(),
            display_name: "GitHub MCP".into(),
            transport: Transport::Stdio {
                command: Some("mcp-github".into()),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            capabilities: vec![EffectCapability::new(
                "effect://mcp-tool/mcp-github/search",
                Purity::Idempotent,
            )],
            status: ProviderStatus::Registered,
        };
        let v = p.to_value();
        let back = EffectProvider::from_value(&v).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn negative_schema_version_is_rejected() {
        let v = Value::Map(BTreeMap::from([
            (
                "effect_path".into(),
                Value::Str("effect://plugin/ext/tool".into()),
            ),
            ("purity".into(), Value::Str("effectful".into())),
            ("schema_version".into(), Value::Int(-1)),
        ]));
        assert!(EffectCapability::from_value(&v).is_none());
    }

    #[test]
    fn malformed_provider_declaration_is_rejected() {
        let base = BTreeMap::from([
            ("id".into(), Value::Str("bad".into())),
            ("display_name".into(), Value::Str("Bad".into())),
            ("trust".into(), Value::Str("sandboxed".into())),
            ("status".into(), Value::Str("registered".into())),
        ]);

        let mut unknown_transport = base.clone();
        unknown_transport.insert(
            "transport".into(),
            Value::Map(BTreeMap::from([(
                "kind".into(),
                Value::Str("telepathy".into()),
            )])),
        );
        assert!(EffectProvider::from_value(&Value::Map(unknown_transport)).is_none());

        let mut bad_cap = base.clone();
        bad_cap.insert("transport".into(), Value::Str("in_process".into()));
        bad_cap.insert(
            "capabilities".into(),
            Value::List(vec![Value::Map(BTreeMap::from([(
                "purity".into(),
                Value::Str("effectful".into()),
            )]))]),
        );
        assert!(EffectProvider::from_value(&Value::Map(bad_cap)).is_none());

        let mut unknown_trust = base;
        unknown_trust.insert("trust".into(), Value::Str("superuser".into()));
        assert!(EffectProvider::from_value(&Value::Map(unknown_trust)).is_none());
    }
}
