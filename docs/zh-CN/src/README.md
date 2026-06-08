# Nexus 手册

Nexus 是面向模型应用的能力运行时。它把模型推理、工具调用、记忆、状态和外部系统映射为 `effect://` 与 `state://` 资源。程序通过 `open()` 编译出的能力句柄访问这些资源。Nexus 的范围是模型调用、工具执行、长期状态和外部协议之间的执行边界；模型训练、应用界面和业务逻辑由调用方或外部组件承担。

这份手册是当前已实现运行时的中文公开叙述文档。它和 Rust API 参考分工不同：

- 用这份手册理解运行时模型、操作边界和工作区结构。
- 用 Rustdoc 查看 Rust 包、模块、类型、trait（特征）、方法和错误的公开契约。
- 随着示例增加，用 `examples/` 和 Rust 包测试作为可执行文档。

英文手册的 HTML 版本在运行 `mdbook build docs` 后位于：
[`docs/book/index.html`](../../book/index.html)。

## 文档层次

| 层次 | 位置 | 用途 |
| --- | --- | --- |
| 概览 | `README.md` / `README.zh-CN.md` | 项目概要、构建命令、运行命令和文档入口。 |
| 手册 | `docs/src/*.md` / `docs/zh-CN/src/*.md` | 运行时概念、操作行为和组件关系。 |
| API 参考 | `target/doc/` | `cargo doc` 生成的 Rust 包和条目契约。 |

需要安装 mdBook 时运行：

```sh
cargo install mdbook
```

生成 Rust API 参考：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

然后打开 `target/doc/index.html`。

构建中文手册：

```sh
mdbook build docs/zh-CN
```

构建英文手册：

```sh
mdbook build docs
```

本地浏览器预览可运行 `mdbook serve docs/zh-CN` 或 `mdbook serve docs`。
中文手册在 `docs/zh-CN/book.toml` 中声明 `language = "zh-CN"`，并加载
`docs/zh-CN/theme/cjk.css` 处理中文字体与行高。

没有安装 `mdbook` 时，`docs/zh-CN/src/` 下的文件仍然是普通 Markdown，可以直接阅读。

## 翻译约定

中文手册优先使用中文术语；Rust 类型名、Rust 包名、配置键、协议字段、命令和路径保持原文，方便回到代码中查找。统一译名见[术语表](glossary.md)。
