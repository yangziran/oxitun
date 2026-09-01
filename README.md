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
- **系统代理接管**：跨平台（macOS / Windows / Linux）一键接管系统级 SOCKS5 代理与 DNS 劫持，退出时确保优雅清理，无残留配置。
- **高可用会话池**：提供基于 Round-Robin 算法调度的多节点 SSH 代理连接池，自动重连、Keep-Alive 检测，彻底告别断线重连痛点。

## 🔒 安全与隐私 (Security)

- **动态主密钥 (Dynamic Master Key)**：所有节点密码均使用本地动态生成的强随机密钥进行 AES-256-GCM 加密存储，彻底告别明文密码泄露风险。
  - **完美向后兼容**：支持回退解密旧版配置遗留的密码。
  - 密钥被安全地存放在系统数据目录中（如 macOS 下的 `~/.config/OxiTun/master.key`），从根源防范逆向分析。
- **开源脱敏设计**：代码库中保留的 `configs/config.yaml` 仅作为脱敏后的样例模板供开发者参考，保护用户隐私。

## ⚡ 硬件加速与优化

- **Native Crypto**：内置 `target-cpu=native` 策略，激活 Apple Silicon (M1/M2/M3) Crypto 扩展或 Intel/AMD AES-NI 硬件加密加速，加解密开销降低 80% 以上。
- **异步全双工 I/O**：重写了底层的 `BidirectionalCopy` 数据桥接模块，支持不等分片刷新机制，最大化降低代理传输的 TTFB（首字节延迟）。
- **流媒体释放**：彻底取消 Nagle 算法 (`set_nodelay(true)`) 优化高码率流媒体（如 YouTube 4K/8K）传输瓶颈，稳定跑满物理带宽。

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
- macOS 系统需安装 Xcode Command Line Tools。

### 💻 方式一：运行桌面版客户端 (GUI)
```bash
# 1. 安装前端依赖
npm install

# 2. 启动开发服务器与 Tauri 客户端 (已默认开启最高优化级别)
npm run tauri dev

# 3. 编译发布为原生应用包 (.app / .dmg)
npm run tauri build
```

### 🖥️ 方式二：运行服务端命令行版 (CLI - 适合无界面的 Linux/软路由)
```bash
# 1. 进入命令行 crate 目录
cd crates/cli

# 2. 直接指定您的配置文件启动代理引擎
cargo run --release -- --config ../../configs/config.yaml

# 提示：您可以使用 RUST_LOG 环境变量来控制输出日志级别，如 RUST_LOG=debug cargo run ...
```

## 📜 许可证

MIT License
