# 文档策略

公开文档只依赖这个仓库中的公开内容即可阅读。

## 内容放置规则

`README.md` / `README.zh-CN.md` 是入口：项目概要、状态、构建命令、运行命令和文档链接。

`docs/` 是英文公开手册：架构、运行时行为、操作边界、配置和组件关系。

`docs/zh-CN/` 是中文公开手册。它翻译和解释公开实现。

Rustdoc 是 API 参考：Rust 包、模块、类型、trait（特征）、函数、方法、错误和字段契约。

测试和示例是可执行文档。行为能用小例子演示时，优先使用可运行例子。

## Rustdoc 规则

Rustdoc 描述已实现行为和公开契约：

- 条目是什么；
- 什么时候使用；
- 接触什么授权或状态；
- 错误行为；
- 相关时说明重放、污点或持久化含义；
- 有帮助时链接真实 Rust 条目，例如 [`TypeName`]。

Rustdoc 依赖公开文件、公开类型和生成的 API 文档。读者可以只靠这些内容理解页面。

## 守护检查

这些检查捕捉常见回归：

```sh
rg -n "(//!|///).*\\x{a7}" crates
rg -n "(//!|///).*[\\p{Han}]" crates
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
cargo test --doc --workspace
mdbook build docs
mdbook build docs/zh-CN
```

前两个检查让公开 Rustdoc 不混入内部笔记标记或中英混杂片段。中文内容应放在 `README.zh-CN.md` 和 `docs/zh-CN/`。后面的命令确保 API 文档、文档测试和两套 mdBook 手册都能构建。
