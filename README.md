# WispOps

AI 原生的服务器运维桌面工具，用 Rust + GPUI 写成。一份 SSH 主机清单、只读的巡检与诊断、一位通过同一套受控工具工作的助手：变更、sudo、破坏性操作在执行前逐主机裁决，密码只交给 SSH，不回显给界面，也不给模型。

> **早期版本（0.1）。** 引擎和采集器有测试覆盖，整条链路用模拟的 SSH 和模型端点跑通过，但还没有在真实服务器、真实模型服务和 macOS 钥匙串上系统验证。第一次使用请先接一台不重要的机器，保持变更 / sudo / 破坏性操作为默认的「询问」，执行前核对审批卡片里的命令。

整体逻辑移植自 DeepSeek Harness 插件 [dsh-wisp-ops](https://github.com/wisp-science/WispOps)；助手的协议层和界面基础件取自 Wisp Paper。

## 安装

从[发布页](https://github.com/xuzhougeng/WispOps/releases/latest)下载：

| 平台 | 文件 | 说明 |
|---|---|---|
| **macOS**，Apple 芯片 | `WispOps-v<版本>-macos-arm64.dmg` | 打开后把 WispOps 拖进「应用程序」 |
| **macOS**，Intel | `WispOps-v<版本>-macos-x64.dmg` | 同上 |
| **Windows** 10 / 11（x64） | `WispOps-v<版本>-windows-x64.zip` | 解压后运行 `WispOps.exe` |
| **Linux**（x64） | `WispOps-v<版本>-linux-x64.tar.gz` | 解压后运行 `wisp-ops`；没有在真机上测试过 |

0.1 没有代码签名：macOS 第一次打开如果提示无法验证开发者或文件已损坏，执行 `xattr -cr /Applications/WispOps.app`；Windows 出现「Windows 已保护你的电脑」时点「更多信息」→「仍要运行」。

### 检查更新

「设置 › 通用 › 更新」：默认在启动时向 GitHub 查询本仓库最新的正式发布（`releases/latest`，忽略草稿和预发布版本），之后每天最多一次；也可以关掉，或点「立即检查」。请求走设置里的全局代理，只带 `WispOps/<版本>` 这个 User-Agent，没有任何个人信息或遥测。结果和检查时间记在数据文件夹的 `updates.json`；检查失败只记下来、在设置里显示，不反复弹提示。

有新版本时，侧栏「设置」上方出现一条可以关掉的提示，设置里显示版本、发布说明的链接和「下载并校验」：把本平台的安装包（上表中的文件）下载到「下载」文件夹，按发布里的 `SHA256SUMS` 校验，校验通过就在访达 / 资源管理器 / 文件管理器里显示出来；校验不通过的文件会被删除并报告，发布里没有 `SHA256SUMS` 就不下载。因为安装包没有签名，WispOps 不会替换正在运行的程序，也不会打开或运行下载的文件：退出后由你自己安装。没有现成安装包的平台（如 Linux / Windows 的 ARM）只给发布页面的链接。

## 从源码运行

需要 Rust（版本见 `rust-toolchain.toml`，rustup 会自动安装）；Windows 上还需要 MSVC 构建工具，Linux 上的系统库见 `scripts/linux-build-deps.sh`。

```sh
cargo run --release                              # 运行
cargo run --release --features runtime_shaders   # Xcode 没装 Metal Toolchain 时用这个
cargo test                                       # 五个 crate 的全部测试
cargo clippy --all-targets                       # 应当没有警告
```

需要本机有 OpenSSH 客户端（`ssh`）。目标主机按 GNU/Linux 处理。

`WISP_OPS_HOME=<目录>` 把数据和 `settings.json` 都放到一个目录里，调试时用它，不碰真实数据。

## 能做什么

| 页面 | 内容 |
|---|---|
| 机群总览 | 每台服务器最近 30 次巡检的状态矩阵，点方块看当次发现；可开自动巡检（只读、不用 sudo、不调用模型） |
| 服务器 | 清单：添加、从 `~/.ssh/config` 导入、能力探测、三项操作权限（allow / ask / deny）、SSH 与 sudo 凭据关联和测试 |
| 磁盘 | 每块磁盘被什么占着的方块图：方块是目录，面积按占用，大方块里显示下一级，点击进入；也可切成列表。第一次扫描选「用户目录」（不需要 root）或「全盘」（以 root 统计每个本地文件系统），之后按间隔自动增量扫描，标出增长的目录 |
| 长时任务 | 各服务器上运行超过阈值（默认 24 小时）的用户进程和 Slurm 作业：谁的、跑了多久、CPU 和内存、是否空闲或已暂停；登录 shell、tmux 这类会话进程不算 |
| 安全 | 最近 24 小时的登录攻击：失败次数、来源地址、尝试的账号、逐小时分布，以及成功登录和其他可疑迹象；认证日志要 root 才能读，能用 root 的服务器自动用 |
| 例行任务 | 把只读检查（巡检、磁盘、目录空间、新增文件、安全排查、自定义只读命令）绑到服务器上，手动或定时运行并记录；报告由助手按需读已采集的结果来写 |
| 操作审计 | 助手、窗口、任务执行的每一条远程命令：风险、授权方式、结果 |
| 密码库 | XChaCha20-Poly1305 加密，密钥在 macOS 钥匙串 / Windows DPAPI / `0600` 文件 |
| 助手 | 常驻右侧。工具：`ops_hosts` `ops_inspect` `ops_exec` `ops_disk` `ops_files` `ops_security` `ops_change` `ops_task` `ops_history`，外加读技能的 `use_skill` |

助手输入框里的 `/inspect`、`/disk`、`/security`、`/files`、`/history`、`/new` 是内置命令。

## 权限模型

每个动作先分级（read / change / destructive，外加 sudo），再逐主机、逐能力裁决，顺序是 **主机策略 > 所属分组中最严的 > 默认**：

- `allow`：直接执行。
- `ask`：助手里出现一张卡片（主机、能力、确切的命令、模型给的理由），可以「允许这一次」「限时允许同类操作」（一次对话内的限时授权，不含破坏性操作）或「不允许」。
- `deny`：绝对拒绝，批准和授权都不能覆盖；不会来问你。

拒绝清单（默认含 `rm -rf /`、fork 炸弹、`chmod 777 /`）在任何情况下都拦截。认证失败后该主机暂停登录 15 分钟，避免被当成暴力破解。模型只能按清单里的名称指定主机。

## 数据

默认在 `~/.wisp-ops/`：

- `inventory.yml`：手写的清单（hosts / groups / tasks），可选；格式与插件相同
- `managed.json`：在界面里添加的服务器、凭据关联、权限覆盖、任务
- `config.json`：可选，覆盖默认配置（`defaultPolicy`、`denyPatterns`、`ssh.*`、`limits.*`、`thresholds.*` 等）
- `vault.json`、`audit/`、`inspections/`、`tasks/`、`conversations/` 等

模型服务和外观在 `settings.json`（macOS：`~/Library/Application Support/WispOps/`），API Key 明文保存、权限 `0600`。

## 结构

| crate | 内容 |
|---|---|
| `crates/engine` | 运维引擎：配置、清单与选择器、风险分级、权限门与限时授权、SSH 运行器、密码库、审计与历史、安全变更、调度。无 GUI、无模型 |
| `crates/collect` | 只读采集器：每个都是「生成脚本 + 解析输出 + 渲染成给模型的文本」的纯函数 |
| `crates/core` | 助手：三种协议的请求体与流解析、模型服务、设置、技能、Markdown |
| `crates/net` | 流式请求（ureq） |
| 根 crate | GPUI 应用：`app.rs`（状态与命令）、`chat.rs`（助手）、`ops.rs`（引擎与采集器的拼接）、`tools.rs`（工具与权限门）、各页面 |

## 相对插件没有做的

检查脚本库与草稿（`ops_script_draft`、`ops_template_draft`）、任务模板库、外部 webhook 通知、WebDAV 设备同步、WispTerm 兼容、服务检查 / 阈值覆盖 / 静音的编辑界面（引擎已支持，可手写 `managed.json`）、cron 调度。
