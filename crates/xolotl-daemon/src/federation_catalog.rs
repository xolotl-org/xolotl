//! Stock host's immutable live method catalog.
//!
//! This only binds implementation. Peer and subject admission lives in the
//! federation call directory and must be configured separately.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    CallAuthorityKey, CallAuthorityRule, CallMethod, CallPath, CallTarget, ExportName,
    FederationCallStore, FederationError, FederationNodeId, FederationSubject, HostedSubject,
    MAX_CALL_INPUT_BYTES, SubjectIssuerId, SubjectPurpose,
};
use xolotl_federation_kernel::{BytesCallCodec, FederationKernelCatalog, FederationKernelMethod};
use xolotl_graph::portable::Import;
use xolotl_kernel::{Bootstrap, CompiledRequestGrantTemplate, PreparedProgram};
use xolotl_sdk::Program;
use xolotl_types::{GrantMethods, GrantRights, Path, ResourceSelector, RightFlags};

use crate::config::{
    FederationCallAuthorityConfig, FederationCallSubjectConfig, FederationGrantFlagConfig,
    FederationMethodCodecConfig, FederationMethodConfig, FederationMethodGrantConfig,
    FederationSubjectIssuerConfig, FederationSubjectPurposeConfig, read_private_bounded_file,
};

const MAX_METHODS: usize = 256;
const MAX_GRANTS_PER_METHOD: usize = 64;
const MAX_PROGRAM_BYTES: u64 = 1024 * 1024;
const MAX_AUTHORITIES: usize = 4096;
const MAX_ISSUER_RULES: usize = 1024;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SubjectIssuerRule {
    pub issuer: SubjectIssuerId,
    pub presenter: FederationNodeId,
    pub purpose: SubjectPurpose,
    pub namespace: String,
}

pub(crate) struct PreparedCallAuthority {
    pub rule: CallAuthorityRule,
    pub expected_revision: Option<u64>,
}

/// The local implementation of exact, versioned contracts. Lookup borrows the
/// digest and checks the whole target, so each call avoids allocating a key.
pub(crate) struct StockFederationCatalog {
    methods: HashMap<[u8; 32], Arc<FederationKernelMethod>>,
}

struct PreparedMethod {
    target: CallTarget,
    program: PreparedProgram,
    identity_path: Path,
    grants: Vec<CompiledRequestGrantTemplate>,
    codec: FederationMethodCodecConfig,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CanonicalGrant {
    selector: String,
    method_mode: u8,
    methods: Vec<String>,
    flags: u32,
}

impl StockFederationCatalog {
    /// Validate all source files and contracts before registering any local
    /// identity. A method with native module imports needs a host-supplied
    /// live StepModule and is therefore outside this stock catalog.
    pub(crate) fn load(config: &[FederationMethodConfig], boot: &Bootstrap) -> Result<Self> {
        ensure!(config.len() <= MAX_METHODS, "too many federation methods");
        let prepared = config.iter().map(prepare).collect::<Result<Vec<_>>>()?;
        for entry in &prepared {
            entry
                .program
                .layout(&boot.kernel().execution_config())
                .context("federation method exceeds current Kernel execution limits")?;
        }
        let mut distinct = std::collections::HashSet::with_capacity(prepared.len());
        ensure!(
            prepared
                .iter()
                .all(|entry| distinct.insert(entry.target.contract_digest)),
            "duplicate federation method contract digest"
        );
        let mut methods = HashMap::with_capacity(prepared.len());
        for entry in prepared {
            let identity = boot
                .kernel()
                .identities()
                .resolve_or_register(&entry.identity_path)
                .with_context(|| {
                    format!(
                        "register federation method acting identity {}",
                        entry.identity_path
                    )
                })?;
            let method = Arc::new(FederationKernelMethod {
                target: entry.target,
                program: entry.program,
                identity,
                grants: entry.grants,
                codec: match entry.codec {
                    FederationMethodCodecConfig::BytesV1 => Arc::new(BytesCallCodec),
                },
            });
            methods.insert(method.target.contract_digest, method);
        }
        Ok(Self { methods })
    }

    pub(crate) fn contains(&self, target: &CallTarget) -> bool {
        self.methods
            .get(&target.contract_digest)
            .is_some_and(|method| method.target == *target)
    }

    pub(crate) fn len(&self) -> usize {
        self.methods.len()
    }
}

impl FederationKernelCatalog for StockFederationCatalog {
    fn resolve(&self, target: &CallTarget) -> Result<Arc<FederationKernelMethod>, FederationError> {
        let method = self
            .methods
            .get(&target.contract_digest)
            .filter(|method| method.target == *target)
            .ok_or(FederationError::NotFound)?;
        Ok(Arc::clone(method))
    }
}

pub(crate) fn parse_authorities(
    config: &[FederationCallAuthorityConfig],
    catalog: &StockFederationCatalog,
    local: FederationNodeId,
    peers: &[FederationNodeId],
    issuers: &[SubjectIssuerRule],
) -> Result<Vec<PreparedCallAuthority>> {
    ensure!(
        config.len() <= MAX_AUTHORITIES,
        "too many federation call authorities"
    );
    let mut output: Vec<PreparedCallAuthority> = Vec::with_capacity(config.len());
    for item in config {
        let presenter =
            FederationNodeId::from_bytes(decode_hex::<48>(&item.presenter, "call presenter")?);
        ensure!(
            presenter != local && peers.contains(&presenter),
            "federation call presenter must be a configured remote peer"
        );
        let subject = match &item.subject {
            FederationCallSubjectConfig::Node => FederationSubject::Node(presenter),
            FederationCallSubjectConfig::Hosted {
                issuer,
                namespace,
                subject,
            } => {
                ensure!(
                    valid_subject_name(namespace) && valid_subject_name(subject),
                    "invalid hosted federation call subject"
                );
                FederationSubject::Hosted(HostedSubject {
                    issuer: SubjectIssuerId::from_bytes(decode_hex::<48>(
                        issuer,
                        "call subject issuer",
                    )?),
                    namespace: namespace.clone(),
                    subject: subject.clone(),
                })
            }
        };
        let rule = CallAuthorityRule {
            subject,
            presenter,
            target: CallTarget {
                export: ExportName::new(item.export.clone())?,
                path: CallPath::new(item.path.clone())?,
                method: CallMethod::new(item.method.clone())?,
                contract_digest: decode_hex::<32>(
                    &item.contract_digest,
                    "call authority contract_digest",
                )?,
            },
            enabled: item.enabled,
            expires_ms: item.expires_ms,
            max_input_bytes: item.max_input_bytes,
            max_prepare_window_ms: item.max_prepare_window_ms,
            max_result_retention_ms: item.max_result_retention_ms,
        };
        rule.validate()?;
        if rule.enabled
            && let FederationSubject::Hosted(hosted) = &rule.subject
        {
            ensure!(
                issuers.iter().any(|issuer| issuer.issuer == hosted.issuer
                    && issuer.presenter == presenter
                    && issuer.namespace == hosted.namespace
                    && issuer.purpose == SubjectPurpose::Invoke),
                "hosted federation call authority requires an explicit Invoke issuer rule"
            );
        }
        ensure!(
            rule.max_input_bytes <= MAX_CALL_INPUT_BYTES as u64,
            "federation call input limit exceeds protocol maximum"
        );
        ensure!(
            !rule.enabled || catalog.contains(&rule.target),
            "enabled federation call authority has no exact local method"
        );
        ensure!(
            item.expected_revision != Some(0),
            "federation call expected_revision must be positive"
        );
        ensure!(
            !output.iter().any(|saved| saved.rule.subject == rule.subject
                && saved.rule.presenter == rule.presenter
                && saved.rule.target == rule.target),
            "duplicate federation call authority"
        );
        output.push(PreparedCallAuthority {
            rule,
            expected_revision: item.expected_revision,
        });
    }
    Ok(output)
}

pub(crate) fn parse_issuer_rules(
    config: &[FederationSubjectIssuerConfig],
    local: FederationNodeId,
    peers: &[FederationNodeId],
) -> Result<Vec<SubjectIssuerRule>> {
    ensure!(
        config.len() <= MAX_ISSUER_RULES,
        "too many federation subject issuer rules"
    );
    let mut rules = Vec::new();
    for item in config {
        let presenter = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.presenter,
            "subject issuer presenter",
        )?);
        ensure!(
            presenter != local,
            "subject issuer presenter must be remote"
        );
        let guest = !peers.contains(&presenter);
        ensure!(
            valid_subject_name(&item.namespace),
            "invalid federation subject issuer namespace"
        );
        ensure!(
            !item.purposes.is_empty() && rules.len() + item.purposes.len() <= MAX_ISSUER_RULES,
            "invalid federation subject issuer purposes"
        );
        let issuer = SubjectIssuerId::from_bytes(decode_hex::<48>(&item.issuer, "subject issuer")?);
        for purpose in &item.purposes {
            let purpose = match purpose {
                FederationSubjectPurposeConfig::Discover => SubjectPurpose::Discover,
                FederationSubjectPurposeConfig::Sync => SubjectPurpose::Sync,
                FederationSubjectPurposeConfig::Invoke => SubjectPurpose::Invoke,
                FederationSubjectPurposeConfig::ObjectRead => SubjectPurpose::ObjectRead,
            };
            ensure!(
                !guest || matches!(purpose, SubjectPurpose::Sync | SubjectPurpose::ObjectRead),
                "unconfigured guest presenter only supports sync or object_read issuer rules"
            );
            let rule = SubjectIssuerRule {
                issuer,
                presenter,
                purpose,
                namespace: item.namespace.clone(),
            };
            ensure!(
                !rules.contains(&rule),
                "duplicate federation subject issuer rule"
            );
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// Reconcile only exact method grants after peer/export policy exists. Removed
/// grants are disabled in place, preserving their key and monotonically
/// advancing revision so old reservations cannot be resurrected.
pub(crate) fn reconcile_authorities(
    store: &dyn FederationCallStore,
    desired: &[PreparedCallAuthority],
) -> Result<()> {
    let desired_keys: HashSet<Vec<u8>> = desired
        .iter()
        .map(|item| CallAuthorityKey::from_rule(&item.rule).encoded())
        .collect::<std::result::Result<_, _>>()?;
    let mut after = None;
    loop {
        let page = store.scan_call_authorities(after.as_ref(), 256)?;
        if page.is_empty() {
            break;
        }
        for entry in &page {
            let key = CallAuthorityKey::from_rule(&entry.rule);
            if entry.rule.enabled && !desired_keys.contains(&key.encoded()?) {
                let mut disabled = entry.rule.clone();
                disabled.enabled = false;
                store.set_call_authority(Some(entry.revision), disabled)?;
            }
        }
        after = page
            .last()
            .map(|entry| CallAuthorityKey::from_rule(&entry.rule));
        if page.len() < 256 {
            break;
        }
    }
    for item in desired {
        let key = CallAuthorityKey::from_rule(&item.rule);
        let current = store.call_authority(&key)?;
        if current
            .as_ref()
            .is_some_and(|entry| entry.rule == item.rule)
        {
            continue;
        }
        ensure!(
            current.as_ref().map(|entry| entry.revision) == item.expected_revision,
            "federation call authority revision conflict"
        );
        if current.is_some() || item.rule.enabled {
            store.set_call_authority(item.expected_revision, item.rule.clone())?;
        }
    }
    Ok(())
}

fn valid_subject_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn prepare(config: &FederationMethodConfig) -> Result<PreparedMethod> {
    let target = CallTarget {
        export: ExportName::new(config.export.clone())?,
        path: CallPath::new(config.path.clone())?,
        method: CallMethod::new(config.method.clone())?,
        contract_digest: decode_hex::<32>(&config.contract_digest, "method contract_digest")?,
    };
    ensure!(
        target.contract_digest != [0; 32],
        "federation method contract_digest must not be zero"
    );
    let identity_path =
        Path::parse(&config.identity_path).context("invalid federation method identity_path")?;
    xolotl_kernel::identity::validate_path(&identity_path)
        .context("federation method identity_path must be a concrete local identity")?;
    ensure!(
        std::path::Path::new(&config.program_path).is_absolute(),
        "federation methods.program_path must be absolute"
    );
    let source = read_private_bounded_file(
        &config.program_path,
        "federation method portable program",
        MAX_PROGRAM_BYTES,
    )?;
    let program = Program::from_json(&source).context("decode federation method program")?;
    let compiled = program
        .compile()
        .context("compile federation method program")?;
    ensure!(
        !compiled
            .imports()
            .iter()
            .any(|import| matches!(import, Import::Module(_))),
        "stock federation method cannot use native module imports"
    );
    let expected_id = decode_hex::<32>(&config.program_id, "method program_id")?;
    ensure!(
        expected_id == compiled.id(),
        "federation method program_id differs from the compiled portable image (actual {})",
        encode_hex(&compiled.id())
    );
    let (grants, canonical_grants) = compile_grants(&config.grants)?;
    let codec = config.codec;
    let actual_contract = contract_digest(
        &target,
        expected_id,
        &identity_path,
        codec,
        &canonical_grants,
    );
    ensure!(
        target.contract_digest == actual_contract,
        "federation method contract_digest differs from its program, identity, codec or grants (actual {})",
        encode_hex(&actual_contract)
    );
    Ok(PreparedMethod {
        target,
        program: PreparedProgram::from_compiled(compiled)
            .context("prepare federation method portable image")?,
        identity_path,
        grants,
        codec,
    })
}

fn compile_grants(
    config: &[FederationMethodGrantConfig],
) -> Result<(Vec<CompiledRequestGrantTemplate>, Vec<CanonicalGrant>)> {
    ensure!(
        config.len() <= MAX_GRANTS_PER_METHOD,
        "too many federation method request grants"
    );
    let mut grants = Vec::with_capacity(config.len());
    for item in config {
        ensure!(
            !item.all_methods || item.methods.is_empty(),
            "federation grant cannot combine all_methods with named methods"
        );
        let selector = ResourceSelector::parse(&item.selector)
            .context("invalid federation method grant selector")?;
        let mut flags = RightFlags::empty();
        for flag in &item.flags {
            let bit = match flag {
                FederationGrantFlagConfig::Clone => RightFlags::CLONE,
                FederationGrantFlagConfig::Transfer => RightFlags::TRANSFER,
                FederationGrantFlagConfig::SpawnWith => RightFlags::SPAWN_WITH,
                FederationGrantFlagConfig::Delegate => RightFlags::DELEGATE,
            };
            ensure!(
                !flags.contains(bit),
                "duplicate federation method grant flag"
            );
            flags.insert(bit);
        }
        let methods = if item.all_methods {
            GrantMethods::all()
        } else {
            GrantMethods::names(item.methods.iter().cloned())
        };
        let rights = GrantRights::new(methods.clone(), flags);
        ensure!(!rights.is_empty(), "empty federation method request grant");
        let canonical = CanonicalGrant {
            selector: selector.pattern.to_string(),
            method_mode: if item.all_methods { 1 } else { 0 },
            methods: methods.selected_names().unwrap_or(&[]).to_vec(),
            flags: flags.bits(),
        };
        grants.push((canonical, CompiledRequestGrantTemplate { selector, rights }));
    }
    grants.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        !grants.windows(2).any(|pair| pair[0].0 == pair[1].0),
        "duplicate federation method request grant"
    );
    let (canonical, compiled) = grants.into_iter().unzip();
    Ok((compiled, canonical))
}

fn contract_digest(
    target: &CallTarget,
    program_id: [u8; 32],
    identity_path: &Path,
    codec: FederationMethodCodecConfig,
    grants: &[CanonicalGrant],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("xolotl.federation.method-contract.v1");
    hash_text(&mut hash, target.export.as_str());
    hash_text(&mut hash, target.path.as_str());
    hash_text(&mut hash, target.method.as_str());
    hash.update(&program_id);
    hash_text(&mut hash, &identity_path.to_string());
    hash_text(
        &mut hash,
        match codec {
            FederationMethodCodecConfig::BytesV1 => "bytes_v1",
        },
    );
    hash.update(&(grants.len() as u32).to_be_bytes());
    for grant in grants {
        hash_text(&mut hash, &grant.selector);
        hash.update(&[grant.method_mode]);
        hash.update(&(grant.methods.len() as u32).to_be_bytes());
        for method in &grant.methods {
            hash_text(&mut hash, method);
        }
        hash.update(&grant.flags.to_be_bytes());
    }
    *hash.finalize().as_bytes()
}

fn hash_text(hash: &mut blake3::Hasher, text: &str) {
    hash.update(&(text.len() as u32).to_be_bytes());
    hash.update(text.as_bytes());
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == 2 * N,
        "federation {label} must be {N} bytes of hex"
    );
    let mut output = [0; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let hex = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        *slot = (hex(pair[0]).context("invalid federation hex")? << 4)
            | hex(pair[1]).context("invalid federation hex")?;
    }
    Ok(output)
}

#[cfg(test)]
pub(crate) fn commit_test_method(config: &mut FederationMethodConfig) -> Result<()> {
    let program = Program::from_json(&std::fs::read(&config.program_path)?)?;
    let program_id = program.compile()?.id();
    let target = CallTarget {
        export: ExportName::new(config.export.clone())?,
        path: CallPath::new(config.path.clone())?,
        method: CallMethod::new(config.method.clone())?,
        contract_digest: [0; 32],
    };
    let (_, grants) = compile_grants(&config.grants)?;
    let identity_path = Path::parse(&config.identity_path)?;
    let digest = contract_digest(&target, program_id, &identity_path, config.codec, &grants);
    config.program_id = encode_hex(&program_id);
    config.contract_digest = encode_hex(&digest);
    Ok(())
}

#[cfg(test)]
mod tests;
