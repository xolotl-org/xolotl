use super::*;
use anyhow::ensure;
use xolotl_sdk::{Expression, Program};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_program(path: &std::path::Path, program: &Program) -> Result<()> {
    std::fs::write(path, serde_json::to_vec(program)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn method_config(path: &std::path::Path, program: &Program) -> Result<FederationMethodConfig> {
    let compiled = program.compile()?;
    let target = CallTarget {
        export: ExportName::new("tools")?,
        path: CallPath::new("/echo")?,
        method: CallMethod::new("echo")?,
        contract_digest: [0; 32],
    };
    let identity_path = Path::parse("identity://federation/echo")?;
    let contract = contract_digest(
        &target,
        compiled.id(),
        &identity_path,
        FederationMethodCodecConfig::BytesV1,
        &[],
    );
    Ok(FederationMethodConfig {
        export: "tools".into(),
        path: "/echo".into(),
        method: "echo".into(),
        contract_digest: hex(&contract),
        program_path: path.to_str().context("test path is not UTF-8")?.into(),
        program_id: hex(&compiled.id()),
        identity_path: identity_path.to_string(),
        codec: FederationMethodCodecConfig::BytesV1,
        grants: vec![],
    })
}

#[test]
fn stock_catalog_resolves_exact_contract_and_reopens_with_same_identity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("echo.json");
    let program = Program::new(Expression::Input);
    write_program(&path, &program)?;
    let config = method_config(&path, &program)?;
    let boot = Bootstrap::in_memory();
    let catalog = StockFederationCatalog::load(std::slice::from_ref(&config), &boot)?;
    ensure!(catalog.len() == 1);
    let target = CallTarget {
        export: ExportName::new(config.export.clone())?,
        path: CallPath::new(config.path.clone())?,
        method: CallMethod::new(config.method.clone())?,
        contract_digest: decode_hex(&config.contract_digest, "test contract")?,
    };
    ensure!(catalog.contains(&target));
    let method = catalog.resolve(&target)?;
    ensure!(method.program.id() == program.compile()?.id());
    ensure!(method.identity != xolotl_types::IdentityRef::ROOT);
    let reopened = StockFederationCatalog::load(&[config], &boot)?;
    ensure!(reopened.resolve(&target)?.identity == method.identity);
    let mut changed = target;
    changed.path = CallPath::new("/other")?;
    ensure!(matches!(
        catalog.resolve(&changed),
        Err(FederationError::NotFound)
    ));
    Ok(())
}

#[test]
fn source_or_contract_drift_is_rejected_before_identity_registration() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("echo.json");
    let mut program = Program::new(Expression::Input);
    write_program(&path, &program)?;
    let config = method_config(&path, &program)?;
    let boot = Bootstrap::in_memory();
    let identity = Path::parse(&config.identity_path)?;
    let mut changed = config.clone();
    changed.identity_path = "identity://federation/changed".into();
    ensure!(StockFederationCatalog::load(&[changed], &boot).is_err());
    ensure!(boot.kernel().identities().lookup(&identity)?.is_none());
    program.body = Expression::literal(3);
    write_program(&path, &program)?;
    ensure!(StockFederationCatalog::load(&[config], &boot).is_err());
    ensure!(boot.kernel().identities().lookup(&identity)?.is_none());
    Ok(())
}

#[test]
fn stock_catalog_rejects_unbound_host_module_programs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("module.json");
    let program = Program::new(Expression::Module {
        module: xolotl_graph::StepRef::new("native"),
    });
    write_program(&path, &program)?;
    let config = method_config(&path, &program)?;
    let boot = Bootstrap::in_memory();
    ensure!(StockFederationCatalog::load(&[config], &boot).is_err());
    Ok(())
}

#[test]
fn method_grants_and_identity_are_bound_into_contract_digest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("echo.json");
    let program = Program::new(Expression::Input);
    write_program(&path, &program)?;
    let mut config = method_config(&path, &program)?;
    config.grants.push(FederationMethodGrantConfig {
        selector: "perform://effect/echo".into(),
        methods: vec!["invoke".into()],
        all_methods: false,
        flags: vec![],
    });
    let boot = Bootstrap::in_memory();
    ensure!(StockFederationCatalog::load(std::slice::from_ref(&config), &boot).is_err());
    let target = CallTarget {
        export: ExportName::new(config.export.clone())?,
        path: CallPath::new(config.path.clone())?,
        method: CallMethod::new(config.method.clone())?,
        contract_digest: [0; 32],
    };
    let (_, grants) = compile_grants(&config.grants)?;
    let digest = contract_digest(
        &target,
        decode_hex(&config.program_id, "test program")?,
        &Path::parse(&config.identity_path)?,
        config.codec,
        &grants,
    );
    config.contract_digest = hex(&digest);
    let catalog = StockFederationCatalog::load(std::slice::from_ref(&config), &boot)?;
    ensure!(catalog.len() == 1);
    config.grants[0]
        .flags
        .push(FederationGrantFlagConfig::Delegate);
    ensure!(StockFederationCatalog::load(&[config], &boot).is_err());
    Ok(())
}

#[test]
fn exact_authority_reconciliation_revokes_removed_rules() -> Result<()> {
    use xolotl_federation::{
        CallAuthorityKey, FederationCallStore as _, MemoryFederationCallStore,
    };

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("echo.json");
    let program = Program::new(Expression::Input);
    write_program(&path, &program)?;
    let method = method_config(&path, &program)?;
    let boot = Bootstrap::in_memory();
    let catalog = StockFederationCatalog::load(std::slice::from_ref(&method), &boot)?;
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let config = FederationCallAuthorityConfig {
        presenter: hex(peer.as_bytes()),
        subject: FederationCallSubjectConfig::Node,
        export: method.export,
        path: method.path,
        method: method.method,
        contract_digest: method.contract_digest,
        enabled: true,
        expires_ms: 10_000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 1000,
        max_result_retention_ms: 2000,
        expected_revision: None,
    };
    let desired = parse_authorities(&[config], &catalog, local, &[peer], &[])?;
    let store = MemoryFederationCallStore::new(local);
    reconcile_authorities(&store, &desired)?;
    let key = CallAuthorityKey::from_rule(&desired[0].rule);
    ensure!(
        store
            .call_authority(&key)?
            .context("missing grant")?
            .rule
            .enabled
    );
    reconcile_authorities(&store, &desired)?;
    ensure!(
        store
            .call_authority(&key)?
            .context("missing grant")?
            .revision
            == 1
    );
    reconcile_authorities(&store, &[])?;
    let revoked = store.call_authority(&key)?.context("missing tombstone")?;
    ensure!(!revoked.rule.enabled && revoked.revision == 2);
    Ok(())
}

#[test]
fn hosted_call_needs_exact_issuer_namespace_presenter_and_purpose() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("echo.json");
    let program = Program::new(Expression::Input);
    write_program(&path, &program)?;
    let method = method_config(&path, &program)?;
    let boot = Bootstrap::in_memory();
    let catalog = StockFederationCatalog::load(std::slice::from_ref(&method), &boot)?;
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let issuer = [3; 48];
    let config = FederationCallAuthorityConfig {
        presenter: hex(peer.as_bytes()),
        subject: FederationCallSubjectConfig::Hosted {
            issuer: hex(&issuer),
            namespace: "app".into(),
            subject: "alice".into(),
        },
        export: method.export,
        path: method.path,
        method: method.method,
        contract_digest: method.contract_digest,
        enabled: true,
        expires_ms: 10_000,
        max_input_bytes: 1024,
        max_prepare_window_ms: 1000,
        max_result_retention_ms: 2000,
        expected_revision: None,
    };
    ensure!(
        parse_authorities(std::slice::from_ref(&config), &catalog, local, &[peer], &[]).is_err()
    );
    let rules = parse_issuer_rules(
        &[FederationSubjectIssuerConfig {
            issuer: hex(&issuer),
            namespace: "app".into(),
            presenter: hex(peer.as_bytes()),
            purposes: vec![FederationSubjectPurposeConfig::Sync],
        }],
        local,
        &[peer],
    )?;
    ensure!(
        parse_authorities(
            std::slice::from_ref(&config),
            &catalog,
            local,
            &[peer],
            &rules
        )
        .is_err()
    );
    let rules = parse_issuer_rules(
        &[FederationSubjectIssuerConfig {
            issuer: hex(&issuer),
            namespace: "app".into(),
            presenter: hex(peer.as_bytes()),
            purposes: vec![FederationSubjectPurposeConfig::Invoke],
        }],
        local,
        &[peer],
    )?;
    ensure!(parse_authorities(&[config], &catalog, local, &[peer], &rules)?.len() == 1);
    Ok(())
}
