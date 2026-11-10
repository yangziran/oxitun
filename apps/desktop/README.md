# OxiTun 🚀

OxiTun 是一款基于 Rust 和 Tauri 构建的高性能 SSH 隧道与 SOCKS5 代理客户端。专为追求极致网络性能、低资源占用与原生体验的用户设计。

## ✨ 核心特性

- **极致性能**：底层采用纯 Rust (`Tokio` + `Russh`) 编写，无缝对接系统级硬件加密指令集。
- **全栈协议支持**：完美支持 IPv4 和 IPv6 双栈网络，彻底告别单栈局限。
- **智能路由分流**：支持全局（Global）、白名单（Whitelist）、黑名单（Blacklist）和直连（Direct）四种路由模式，支持自定义 CIDR/域名规则。
- **系统代理接管**：一键自动设置并恢复 macOS 等操作系统的系统级 SOCKS5 代理，退出时优雅清理。
- **直观易用**：基于 Vue 3 打造的现代化 GUI 界面，支持多节点管理、状态实时监控、自动重连与 Keep-Alive 存活检测。
- **低延迟传输**：通过异步全双工 I/O 与 TCP 缓冲调优优化代理传输。
- **安全可靠**：节点密码等敏感配置在本地通过动态生成的 AES-256-GCM 强密钥加密存储。

## 🔒 安全与隐私 (Security)

- **动态主密钥 (Dynamic Master Key)**：为了保证代码开源后的绝对安全，所有节点密码均使用本地动态生成的强密钥进行 AES-256-GCM 加密存储。
  - **自动生成**：首次启动时，程序会通过操作系统的安全随机数发生器生成 256 位高强度密钥，保存在用户的本地应用配置目录（如 macOS 的 `~/Library/Application Support/OxiTun/master.key`）。
  - **备份与恢复**：可备份 `master.key` 用于恢复；更换或丢失密钥会使既有密码密文失效，需要重新填写节点密码。
  - **防源码逆向**：开源代码中不包含任何硬编码密钥，从根本上杜绝了密钥被反编译泄露的风险。

## ⚡ 硬件加速与优化

- **Native Crypto**：支持开启 `target-cpu=native`，激活 Apple Silicon (M1/M2/M3) Crypto 扩展或 Intel AES-NI 硬件加密加速。
- **流媒体优化**：为高码率流媒体（如 YouTube 1080P/4K/8K）提供底层的多路复用与大文件传输优化，稳定跑满物理宽带。
- **LTO 极限编译**：Release 模式下采用 `opt-level = 3` 与跨链接时优化 (`LTO`)，构建极致紧凑且高效的二进制执行文件。

## 🛠️ 技术栈

- **前端**：[Vue 3](https://vuejs.org/) + [TypeScript](https://www.typescriptlang.org/) + [Vite](https://vitejs.dev/)
- **应用框架**：[Tauri 2](https://v2.tauri.app/)
- **核心网络**：[Rust](https://www.rust-lang.org/) + [Tokio](https://tokio.rs/) + [Russh](https://github.com/warp-tech/russh)

## 📦 编译与运行

### 环境准备
- [Node.js](https://nodejs.org/) (推荐 v18+)
- [Rust](https://www.rust-lang.org/tools/install) (最新 Stable 版本)
- 操作系统原生构建工具 (macOS 需安装 Xcode Command Line Tools)

### 开发模式 (Dev)
```bash
# 1. 安装前端依赖
npm install

# 2. 启动开发服务器与 Tauri 客户端
npm run tauri dev
```

### 打包发布 (Build)
```bash
# 编译并打包为系统原生应用程序 (Mac .app / .dmg)
npm run tauri build
```
> **提示**：正式打包构建时，建议确保已应用 `Cargo` 的 `release` 配置，以获得最顶级的软硬件协同性能。

## 📝 目录结构

- `apps/desktop/` - Tauri 客户端与 Vue 前端源码
- `crates/core/` - Rust 核心代理层 (网络栈、加解密、系统代理、路由引擎)
- `crates/cli/` - Headless 服务端，支持配置热加载与 launchd / systemd / Windows Service 系统服务注册
- `configs/` - 配置文件示例与约定

## 📜 许可证

MIT License
