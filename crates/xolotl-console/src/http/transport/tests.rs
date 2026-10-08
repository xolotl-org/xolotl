use super::*;
use crate::{
    ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig,
};
use anyhow::ensure;
use axum::http::HeaderValue;

fn proxy_config(peers: &[&str]) -> anyhow::Result<ConsoleTransportSecurityConfig> {
    Ok(ConsoleTransportSecurityConfig {
        mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
        trusted_proxy: ConsoleTrustedProxyConfig {
            peers: peers
                .iter()
                .map(|peer| peer.parse())
                .collect::<Result<_, _>>()?,
            ..Default::default()
        },
        unsafe_relaxations: Vec::new(),
    })
}

fn forwarded(values: &[&str]) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append("x-forwarded-for", value.parse()?);
    }
    Ok(headers)
}

#[test]
fn untrusted_prefixes_cannot_change_the_source_or_evade_its_connection_limit() -> anyhow::Result<()>
{
    use crate::http::{ConsoleWsConfig, ConsoleWsLimit, config::ConsoleWsRuntime};

    let config = proxy_config(&["127.0.0.1"])?;
    let peer = "127.0.0.1:9000".parse()?;
    let admission = ConsoleWsRuntime::new(ConsoleWsConfig {
        max_connections_per_source: 1,
        ..Default::default()
    });
    let first = verified_source_addr(&forwarded(&["spoof-a, 198.51.100.2"])?, Some(peer), &config);
    ensure!(admission.try_acquire_source(&first).is_ok());
    for prefix in ["spoof-b", "203.0.113.8", "", "unknown, , [::1]"] {
        let headers = forwarded(&[&format!("{prefix}, 198.51.100.2")])?;
        let source = verified_source_addr(&headers, Some(peer), &config);
        ensure!(source == "198.51.100.2");
        ensure!(admission.try_acquire_source(&source) == Err(ConsoleWsLimit::Source));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_bytes(b"\xff, 198.51.100.2")?,
    );
    ensure!(verified_source_addr(&headers, Some(peer), &config) == first);
    admission.release_source(&first);
    Ok(())
}

#[test]
fn trusted_suffixes_follow_repeated_header_order_and_stop_at_the_first_untrusted_hop()
-> anyhow::Result<()> {
    let config = proxy_config(&["127.0.0.1", "192.0.2.10", "192.0.2.11"])?;
    let peer = "127.0.0.1:9000".parse()?;
    for values in [
        vec!["spoof, 198.51.100.2, 192.0.2.10, 192.0.2.11"],
        vec!["spoof", "198.51.100.2, 192.0.2.10", "192.0.2.11"],
        vec!["spoof, 198.51.100.2", "192.0.2.10, 192.0.2.11"],
    ] {
        ensure!(verified_source_addr(&forwarded(&values)?, Some(peer), &config) == "198.51.100.2");
    }
    let mut headers = forwarded(&["198.51.100.2, 192.0.2.10"])?;
    headers.insert("x-real-ip", "203.0.113.8".parse()?);
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "198.51.100.2");
    Ok(())
}

#[test]
fn an_entirely_trusted_chain_retains_its_leftmost_address() -> anyhow::Result<()> {
    let config = proxy_config(&["127.0.0.1", "192.0.2.10", "192.0.2.11"])?;
    let peer = "127.0.0.1:9000".parse()?;
    let headers = forwarded(&["192.0.2.10", "192.0.2.11"])?;
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "192.0.2.10");
    Ok(())
}

#[test]
fn ipv6_addresses_are_parsed_and_canonicalized_at_every_hop() -> anyhow::Result<()> {
    let config = proxy_config(&["::1", "2001:db8::10"])?;
    let peer = "[::1]:9000".parse()?;
    let headers = forwarded(&[
        "spoof, 2001:0db8:0000:0000:0000:0000:0000:0002",
        " 2001:0db8:0:0:0:0:0:0010 ",
    ])?;
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "2001:db8::2");
    Ok(())
}

#[test]
fn malformed_trusted_suffixes_use_the_socket_peer_without_trying_real_ip() -> anyhow::Result<()> {
    let config = proxy_config(&["127.0.0.1", "192.0.2.10"])?;
    let peer = "127.0.0.1:9000".parse()?;
    for values in [
        vec![""],
        vec![" "],
        vec![","],
        vec!["unknown"],
        vec!["198.51.100.2,"],
        vec!["198.51.100.2,, 192.0.2.10"],
        vec!["198.51.100.2", "", "192.0.2.10"],
        vec!["198.51.100.2, [2001:db8::2]"],
        vec!["198.51.100.2, 192.0.2.10:8080"],
        vec!["198.51.100.2, 999.1.1.1"],
        vec!["198.51.100.2, unknown, 192.0.2.10"],
    ] {
        let mut headers = forwarded(&values)?;
        headers.insert("x-real-ip", "203.0.113.8".parse()?);
        ensure!(verified_source_addr(&headers, Some(peer), &config) == "127.0.0.1");
    }
    let mut headers = forwarded(&["198.51.100.2"])?;
    headers.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff")?);
    headers.insert("x-real-ip", "203.0.113.8".parse()?);
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "127.0.0.1");
    Ok(())
}

#[test]
fn real_ip_is_only_a_single_canonical_address_without_forwarded_for() -> anyhow::Result<()> {
    let config = proxy_config(&["127.0.0.1"])?;
    let peer = "127.0.0.1:9000".parse()?;
    for (values, expected) in [
        (vec![" 198.51.100.2 "], "198.51.100.2"),
        (vec!["2001:0db8:0:0:0:0:0:2"], "2001:db8::2"),
        (vec![""], "127.0.0.1"),
        (vec!["unknown"], "127.0.0.1"),
        (vec!["198.51.100.2, 203.0.113.8"], "127.0.0.1"),
        (vec!["198.51.100.2", "198.51.100.2"], "127.0.0.1"),
        (vec!["198.51.100.2", "203.0.113.8"], "127.0.0.1"),
    ] {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-real-ip", value.parse()?);
        }
        ensure!(verified_source_addr(&headers, Some(peer), &config) == expected);
    }
    Ok(())
}

#[test]
fn missing_or_untrusted_peers_and_disabled_forwarding_ignore_all_source_headers()
-> anyhow::Result<()> {
    let mut config = proxy_config(&["127.0.0.1"])?;
    let mut headers = forwarded(&["203.0.113.8"])?;
    headers.insert("x-real-ip", "198.51.100.2".parse()?);
    let untrusted = "192.0.2.1:9000".parse()?;
    ensure!(verified_source_addr(&headers, Some(untrusted), &config) == "192.0.2.1");
    ensure!(verified_source_addr(&headers, None, &config) == "unknown");
    let peer = "127.0.0.1:9000".parse()?;
    config.trusted_proxy.honor_x_forwarded_for = false;
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "127.0.0.1");
    config.trusted_proxy.honor_x_forwarded_for = true;
    config.mode = ConsoleTransportSecurityMode::LocalTrusted;
    ensure!(verified_source_addr(&headers, Some(peer), &config) == "127.0.0.1");
    Ok(())
}

fn origin_headers() -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "127.0.0.1:9000".parse()?);
    headers.insert(header::ORIGIN, "https://console.example.com".parse()?);
    headers.insert("x-forwarded-host", "console.example.com".parse()?);
    headers.insert("x-forwarded-proto", "https".parse()?);
    Ok(headers)
}

#[test]
fn default_ports_and_ipv6_spellings_have_one_origin_identity() -> anyhow::Result<()> {
    let config = crate::http::console_transport_default();
    for (host, origin) in [
        ("console.example.com", "https://console.example.com:443"),
        ("console.example.com:443", "https://console.example.com"),
        ("console.example.com", "http://console.example.com:80"),
        ("console.example.com:80", "http://console.example.com"),
        ("[2001:db8::1]:443", "https://[2001:0db8:0:0:0:0:0:1]"),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse()?);
        headers.insert(header::ORIGIN, origin.parse()?);
        ensure!(validate_http_auth_headers(&headers, None, &config).is_ok());
        ensure!(validate_upgrade_headers(&headers, None, &config).is_ok());
    }
    for (host, origin) in [
        ("console.example.com:8080", "https://console.example.com"),
        ("console.example.com", "https://console.example.com:80"),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse()?);
        headers.insert(header::ORIGIN, origin.parse()?);
        ensure!(validate_http_auth_headers(&headers, None, &config).is_err());
        ensure!(validate_upgrade_headers(&headers, None, &config).is_err());
    }
    Ok(())
}

#[test]
fn origin_and_host_must_each_be_one_unambiguous_authority() -> anyhow::Result<()> {
    let mut config = proxy_config(&["127.0.0.1"])?;
    let peer = Some("127.0.0.1:9000".parse()?);
    for relaxed in [false, true] {
        config.unsafe_relaxations = if relaxed {
            vec![crate::ConsoleUnsafeTransportRelaxation::RelaxedOrigin]
        } else {
            Vec::new()
        };
        for (name, value) in [
            (header::ORIGIN, "https://attacker.example.com"),
            (header::HOST, "attacker.example.com"),
        ] {
            let mut headers = origin_headers()?;
            headers.append(name, value.parse()?);
            ensure!(validate_http_auth_headers(&headers, peer, &config).is_err());
            ensure!(validate_upgrade_headers(&headers, peer, &config).is_err());
        }
        for (name, value) in [
            (
                header::ORIGIN,
                "https://console.example.com, https://attacker.example.com",
            ),
            (header::HOST, "console.example.com, attacker.example.com"),
        ] {
            let mut headers = origin_headers()?;
            headers.insert(name, value.parse()?);
            ensure!(validate_http_auth_headers(&headers, peer, &config).is_err());
            ensure!(validate_upgrade_headers(&headers, peer, &config).is_err());
        }
    }
    Ok(())
}

#[test]
fn originless_http_keeps_host_and_trusted_forwarded_authority_checks() -> anyhow::Result<()> {
    let config = proxy_config(&["127.0.0.1"])?;
    let peer = Some("127.0.0.1:9000".parse()?);
    let mut headers = origin_headers()?;
    headers.remove(header::ORIGIN);
    ensure!(validate_http_request_headers(&headers, peer, &config, true).is_ok());
    ensure!(validate_http_request_headers(&headers, peer, &config, false).is_err());
    ensure!(validate_upgrade_headers(&headers, peer, &config).is_err());

    for name in [header::HOST, header::ORIGIN] {
        let mut supplied = headers.clone();
        supplied.append(name, "https://attacker.invalid".parse()?);
        ensure!(validate_http_request_headers(&supplied, peer, &config, true).is_err());
    }
    for name in ["x-forwarded-host", "x-forwarded-proto"] {
        let mut duplicated = headers.clone();
        duplicated.append(name, "other".parse()?);
        ensure!(validate_http_request_headers(&duplicated, peer, &config, true).is_err());
    }
    Ok(())
}

#[test]
fn origin_and_host_reject_non_authority_syntax() -> anyhow::Result<()> {
    let config = crate::http::console_transport_default();
    for origin in [
        "https://console.example.com?next=attacker",
        "https://console.example.com#fragment",
        "https://user@console.example.com",
        "https://console.example.com ",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.example.com".parse()?);
        headers.insert(header::ORIGIN, origin.parse()?);
        ensure!(validate_http_auth_headers(&headers, None, &config).is_err());
        ensure!(validate_upgrade_headers(&headers, None, &config).is_err());
    }
    for host in [
        "user@console.example.com",
        "console.example.com/path",
        "[not-ipv6]",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse()?);
        headers.insert(header::ORIGIN, "https://console.example.com".parse()?);
        ensure!(validate_http_auth_headers(&headers, None, &config).is_err());
        ensure!(validate_upgrade_headers(&headers, None, &config).is_err());
    }
    Ok(())
}

#[test]
fn forwarded_authority_headers_require_one_overwritten_value() -> anyhow::Result<()> {
    let mut config = proxy_config(&["127.0.0.1"])?;
    let peer = "127.0.0.1:9000".parse()?;
    let baseline = origin_headers()?;
    ensure!(validate_http_auth_headers(&baseline, Some(peer), &config).is_ok());
    ensure!(validate_upgrade_headers(&baseline, Some(peer), &config).is_ok());
    for (name, valid, other) in [
        (
            "x-forwarded-host",
            "console.example.com",
            "attacker.example",
        ),
        ("x-forwarded-proto", "https", "http"),
    ] {
        for values in [
            vec![format!("{valid},{other}")],
            vec![format!("{other},{valid}")],
            vec![valid.into(), other.into()],
            vec![other.into(), valid.into()],
            vec![valid.into(), valid.into()],
            vec![String::new()],
        ] {
            let mut headers = baseline.clone();
            headers.remove(name);
            for value in values {
                headers.append(name, value.parse()?);
            }
            for relaxed in [false, true] {
                config.unsafe_relaxations = if relaxed {
                    vec![crate::ConsoleUnsafeTransportRelaxation::RelaxedOrigin]
                } else {
                    Vec::new()
                };
                ensure!(validate_http_auth_headers(&headers, Some(peer), &config).is_err());
                ensure!(validate_upgrade_headers(&headers, Some(peer), &config).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn forwarded_authority_headers_are_ignored_without_peer_trust_or_when_disabled()
-> anyhow::Result<()> {
    let mut config = proxy_config(&["127.0.0.1"])?;
    let mut headers = origin_headers()?;
    headers.insert(header::HOST, "console.example.com".parse()?);
    headers.append("x-forwarded-host", "attacker.example".parse()?);
    headers.append("x-forwarded-proto", "invalid".parse()?);
    for peer in [None, Some("192.0.2.1:9000".parse()?)] {
        ensure!(validate_http_auth_headers(&headers, peer, &config).is_ok());
        ensure!(validate_upgrade_headers(&headers, peer, &config).is_ok());
    }
    config.trusted_proxy.honor_x_forwarded_host = false;
    config.trusted_proxy.honor_x_forwarded_proto = false;
    let peer = Some("127.0.0.1:9000".parse()?);
    ensure!(validate_http_auth_headers(&headers, peer, &config).is_ok());
    ensure!(validate_upgrade_headers(&headers, peer, &config).is_ok());
    Ok(())
}
