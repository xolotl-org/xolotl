# Documentation Policy

Public documentation is readable from this repository alone.

## What Goes Where

`README.md` is the entry point: project summary, status, build commands, run
commands, and documentation links.

`docs/` is the English public manual: architecture, runtime behavior,
operational boundaries, configuration, and how the pieces fit together.

`docs/zh-CN/` is the Chinese public manual. It translates and explains public
implementation behavior.

Rustdoc is the API reference: crate, module, type, trait, function, method,
error, and field contracts.

Tests and examples are executable documentation. Prefer a small runnable example
over a long prose explanation when behavior can be demonstrated directly.

## Rustdoc Rules

Rustdoc describes implemented behavior and public contracts:

- what the item is;
- when to use it;
- what authority or state it touches;
- error behavior;
- replay, taint, or durability implications when relevant;
- links to real Rust items such as [`TypeName`] when useful.

Rustdoc relies on public files, public Rust items, and generated API docs.
Readers can understand a page from those materials.

## Guard Checks

These checks catch common regressions:

```sh
rg -n "(//!|///).*\\x{a7}" crates
rg -n "(//!|///).*[\\p{Han}]" crates
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
cargo test --doc --workspace
mdbook build docs
mdbook build docs/zh-CN
```

The first two checks keep public Rustdoc free of internal note markers and
mixed-language fragments. Repository-local checks for non-public path patterns
belong in CI or local scripts. The remaining checks keep API docs, doc tests,
and both mdBook manuals buildable.
