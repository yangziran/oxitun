# OxiTun 🚀

OxiTun 是一款基于 Rust 和 Tauri 构建的高性能 SSH 隧道与多协议代理客户端。专为追求极致网络性能、低资源占用与原生体验的用户设计。它提供**桌面级 GUI 图形端**与**服务端级 Headless CLI 纯净端**，可完美部署于个人电脑、软路由及无界面的 Linux 服务器。

## ✨ 核心特性

- **双端架构**：支持交互丰富的 Tauri/Vue 图形界面客户端，以及极简、纯净、无任何冗余依赖的 CLI 命令行服务端。
- **极致性能**：底层采用纯 Rust (`Tokio` + `Russh`) 编写，无缝对接系统级硬件加密指令集。
- **多维度隧道代理支持**：
  - **SOCKS5 代理 (Dynamic Forwarding)**：标准动态代理转发，支持 IPv4 / IPv6 双栈与域名解析。
  - **本地与远程穿透 (Local/Remote Forwarding)**：支持将远端端口映射到本地，或将本地端口反向穿透暴露给公网。
  - **高级 DNS 隧道 (DNS Proxy)**：内置高性能 DNS 引擎（基于 Moka 缓存），支持传统 DNS over TCP，以及高安全性的 **DNS over TLS (DoT)** 和 **DNS over HTTPS (DoH)** 协议。
- **智能网络分流引擎**：
  - 支持 全局 (Global) / 直连 (Direct) / 白名单 (Whitelist) / 黑名单 (Blacklist) 模式。
  - **高级规则**：内置局域网 (Bypass LAN) 自动绕行，以及基于大容量 CIDR 二分查找的大陆 IP 直连路由表 (`chnroutes`) 支持。
- **系统代理接管**：跨平台（macOS / Windows / Linux）接管系统级 SOCKS5 代理（macOS 额外支持在有 DNS 隧道时接管 DNS），**退出时自动还原到接管前的配置，不残留、不覆盖用户原有代理设置**。
- **高可用会话池**：提供基于 Round-Robin 算法调度的多节点 SSH 代理连接池，自动重连、Keep-Alive 检测，彻底告别断线重连痛点。

## 🔒 安全与隐私 (Security)

- **动态主密钥 (Dynamic Master Key)**：节点密码使用本地动态生成的强随机密钥进行 AES-256-GCM 加密存储——桌面端保存后配置文件中的密码为密文；CLI 场景请自行保护配置文件权限。
  - 密钥被安全地存放在系统数据目录中（macOS 下为 `~/Library/Application Support/OxiTun/master.key`），Unix/macOS 下文件权限收紧为仅当前用户可读写（0600），其他平台依赖系统默认 ACL。
- **开源脱敏设计**：代码库中保留的 `configs/config.yaml` 仅作为脱敏后的样例模板供开发者参考，保护用户隐私。

## ⚡ 硬件加速与优化

- **可选 Native Crypto**：提供 `target-cpu=native` 构建选项（见 `.cargo/config.toml`，默认关闭以兼容旧 CPU），可激活 Apple Silicon (M1/M2/M3) Crypto 扩展或 Intel/AMD AES-NI 硬件加密加速。
- **异步全双工 I/O**：重写了底层的 `BidirectionalCopy` 数据桥接模块，支持不等分片刷新与半关闭传播，降低代理传输的 TTFB（首字节延迟）。
- **流媒体释放**：取消 Nagle 算法 (`set_nodelay(true)`)，配合 TCP 缓冲调优，改善高码率流媒体传输体验。

## 🛠️ 技术栈

- **前端界面**：[Vue 3](https://vuejs.org/) + [TypeScript](https://www.typescriptlang.org/) + [Vite](https://vitejs.dev/)
- **应用框架**：[Tauri 2](https://v2.tauri.app/)
- **核心网络**：[Rust](https://www.rust-lang.org/) + [Tokio](https://tokio.rs/) + [Russh](https://github.com/warp-tech/russh)
- **命令行工具**：[Clap](https://docs.rs/clap/) + [Env Logger](https://docs.rs/env_logger/)

## 📝 目录结构

- `apps/desktop/` - 面向日常用户的 Tauri 客户端与 Vue 图形化前端源码。
- `crates/core/` - OxiTun 的最强心脏：Rust 核心代理层 (涵盖网络协议栈、AES加密、系统代理挂载、智能路由引擎)。
- `crates/cli/` - 面向硬核极客与服务器环境的极简纯命令行工具（构建物极小，不含任何前端冗余）。
- `configs/` - 脱敏后的配置文件参考模板 (`config.yaml`)。

## 📦 编译与运行

### 准备工作
- Node.js (推荐 v18+)
- Rust (最新 Stable 版本)
- macOS 系统需安装 Xcode Command Line Tools

### 方式零：Makefile 一键编译（推荐）

项目根目录提供 `Makefile`，自动做版本一致性检查（`scripts/check-version.sh`）后编译：

```bash
# 当前平台 CLI（产物在 bin/oxitun-cli）
make build-cli

# 当前平台 GUI（产物在 target/release/bundle/，src-tauri 为 workspace 成员）
make build-gui

# CLI 各平台（交叉编译；Linux 用 musl 静态链接，Windows 需 MSVC 链）
make build-cli-mac     # bin/oxitun-cli-macos-{amd64,arm64}
make build-cli-linux   # bin/oxitun-cli-linux-{amd64,arm64}
make build-cli-win     # bin/oxitun-cli-windows-amd64.exe

# 本机 CLI + GUI 全部
make build

# 发布前检查（版本一致性 + fmt + clippy + 测试 + vue-tsc）
make release

# 清理（保留依赖缓存，下次构建快）
make clean

# 全清（包括依赖编译产物，下次需重新编译全部依赖，registry 下载缓存保留；CI 或磁盘紧张时用）
make clean-all
```

> GUI 各平台安装包（.dmg / .deb / .msi 等）由 Tauri 依赖对应平台 SDK 生成，需在本机或 CI 对应平台 runner 上构建；打 `v*` tag 会触发 `.github/workflows/release.yml` 自动产出 macOS/Linux 各 amd64、arm64 及 Windows amd64，共 5 个 CLI 产物与对应桌面安装包。

### 💻 方式一：运行桌面版客户端 (GUI)
```bash
# 1. 安装前端依赖
cd apps/desktop && npm install

# 2. 启动开发服务器与 Tauri 客户端
npm run tauri dev

# 3. 编译发布为原生应用包 (.app / .dmg)
npm run tauri build
```

### 🖥️ 方式二：运行服务端命令行版 (CLI - 适合无界面的 Linux/软路由)
```bash
# 1. 构建（或使用 make build-cli）
cargo build -p oxitun-cli --release

# 2. 复制样例配置为根目录 config.yaml（或 configs/config.local.yaml），两者均已被
#    .gitignore 忽略，避免直接修改受跟踪的样例而误提交凭据，然后编辑填入您的服务器信息
cp configs/config.yaml config.yaml

# 3. 指定您的配置文件启动代理引擎
./target/release/oxitun-cli --config config.yaml

# 提示：您可以使用 RUST_LOG 环境变量来控制输出日志级别，如 RUST_LOG=debug ./target/release/oxitun-cli ...
```

#### CLI 运维速览

- **热加载**：运行中向进程发送 `SIGHUP`（如 `kill -HUP <pid>`）即可进行带校验与回滚的热加载（仅 Unix 支持）；`general` 段字段（如 `metrics_addr`、`chnroute_url` 等）不参与热加载，修改后需重启进程才生效。隧道启动失败时服务器/路由或部分隧道可能已按新配置生效，基线以实际运行状态为准。
- **系统服务**：`oxitun-cli service install --config <配置文件路径>` 将 CLI 注册为系统服务（launchd / systemd / Windows Service，开机自启），随后用 `oxitun-cli service start|stop|restart|status|uninstall` 管理。
- **主机密钥（TOFU）**：默认严格验证主机密钥，首次连接需交互确认；无人值守部署请在配置中预置 `host_key`（形如 `SHA256:xxxx` 的指纹）完成首次信任。`--accept-new-host-key` 可自动信任新主机，仅适合首次信任场景，指纹发生变化时仍会被拒绝。
- **监控指标**：在配置中设置 `general.metrics_addr`（如 `127.0.0.1:9090`）后启动 Prometheus 指标监听，访问 `http://<metrics_addr>/metrics` 获取运行指标。
- **局域网共享风险**：`tunnels[].share_on_lan` 开启后代理将绑定全部网络接口（`0.0.0.0` / `[::]`），且 SOCKS5 无任何认证，在公网环境会形成开放代理，任何人都可以滥用你的节点。仅在可信局域网内按需开启，公网机器严禁开启。

## 📜 许可证

MIT License
