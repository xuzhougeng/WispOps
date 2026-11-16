# 第三方组件与素材

WispOps 本体以 MIT 协议发布（见 [LICENSE](LICENSE)）。下面是随仓库一起分发的第三方代码和素材。Cargo 依赖各自的许可见 `cargo metadata`，这里不逐项列出。

## vendor/

`vendor/gpui`、`vendor/taffy`、`vendor/xattr` 与 Wisp Paper 相同，取自 [quiet-md](https://github.com/s1dashu/quiet-md)（MIT，Copyright (c) 2026 s1dashu）的 `vendor/` 目录：分别是 crates.io 上的 gpui 0.2.2、taffy 0.9.0、xattr 0.2.3 加上 quiet-md 的本地补丁（Windows 输入法、中文避头尾换行等），补丁清单见 [vendor/PATCHES.md](vendor/PATCHES.md)。

| 目录 | 上游 | 许可 |
|---|---|---|
| `vendor/gpui` | [gpui](https://crates.io/crates/gpui) 0.2.2，Zed Industries | Apache-2.0（`vendor/gpui/LICENSE-APACHE`） |
| `vendor/taffy` | [taffy](https://crates.io/crates/taffy) 0.9.0 | MIT（`vendor/taffy/LICENSE.md`） |
| `vendor/xattr` | [xattr](https://crates.io/crates/xattr) 0.2.3 | MIT / Apache-2.0 |

## 源码

- 运维逻辑（清单与选择器、风险分级、权限门、SSH 运行器、密码库、审计、采集脚本与解析）移植自 DeepSeek Harness 插件 [dsh-wisp-ops](https://github.com/wisp-science/WispOps)。
- 助手的协议层（`crates/core`、`crates/net`）和界面基础件（文本输入框、Markdown、设置页的控件、资源嵌入）取自 [Wisp Paper](https://github.com/xuzhougeng/WispPaper)（MIT）；其中输入框参考了 gpui 的 `examples/input.rs`（Apache-2.0）和 quiet-md 的 `src/input.rs`（MIT），Markdown 的读法、`build.rs` 与 `src/assets.rs` 的资源嵌入、设置页的布局来自 quiet-md（MIT）。
- `scripts/` 和发布工作流取自 Wisp Paper；其中的签名步骤与 `scripts/sign-windows-esigner.ps1` 最初来自 [BiblioCell](https://github.com/xuzhougeng/BiblioCell)。

## 图标

`assets/icons/*.svg` 除 `provider-*.svg` 外全部来自 [Lucide](https://lucide.dev/)（ISC 许可，见 `assets/icons/LICENSE-lucide`），文件名按用途改过。

`assets/icons/provider-{deepseek,kimi,glm,claude,openai}.svg` 是各模型服务的标志，取自 [lobe-icons](https://github.com/lobehub/lobe-icons)（MIT 许可），只用来在 设置 › AI 里认出是哪家的服务；标志本身归各自的公司所有。`provider-custom.svg` 是 Lucide 的 server。`provider-{ark,gemini,typesafe}.svg` 为 Wisp Paper 绘制，所指的标志归各自的公司所有。

`assets/branding/` 里的应用图标为本项目绘制。
