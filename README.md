# OxiTun 🚀

OxiTun 是一款基于 Rust 和 Tauri 构建的高性能 SSH 隧道与 SOCKS5 代理客户端。专为追求极致网络性能、低资源占用与原生体验的用户设计。它提供**桌面级 GUI 图形端**与**服务端级 Headless CLI 纯净端**，可完美部署于个人电脑、软路由及无界面的 Linux 服务器。

## ✨ 核心特性

- **双端架构**：支持交互丰富的 Tauri/Vue 图形界面客户端，以及极简、纯净、无任何冗余依赖的 CLI 命令行服务端。
- **极致性能**：底层采用纯 Rust (`Tokio` + `Russh`) 编写，无缝对接系统级硬件加密指令集。
- **全栈协议支持**：完美支持 IPv4 和 IPv6 双栈网络，彻底告别单栈局限（支持 `[::1]` 规范）。
- **智能路由分流**：内置强大的路由引擎，支持 PAC 模式（自动分流）、全局代理和直连模式，支持自定义 CIDR / 域名黑白名单，且能智能绕过局域网（Bypass LAN）。
- **标准端口设定**：统一且规范的本地 SOCKS5 监听端口标准（`1080`），与绝大多数代理生态无缝对接。
- **系统代理接管**：一键自动设置并恢复 macOS 等操作系统的系统级 SOCKS5 代理，退出或收到 `Ctrl+C` 中断时触发优雅清理逻辑，绝不留僵尸进程。
- **自动重连与并发**：多路复用 SSH 会话，提供自动重连与 Keep-Alive 存活检测，彻底解决长连接掉线痛点。

## 🔒 安全与隐私 (Security)

- **动态主密钥 (Dynamic Master Key)**：为了保证代码开源后的绝对安全，所有节点密码均使用本地动态生成的强密钥进行 AES-256-GCM 加密存储。
  - **自动生成**：首次启动时，程序会通过操作系统的安全随机数发生器生成 256 位高强度密钥，保存在用户的本地应用配置目录（如 macOS 的 `~/Library/Application Support/OxiTun/master.key`）。
  - **防源码逆向**：开源代码中不包含任何硬编码密钥，从根本上杜绝了密钥被反编译泄露的风险，并将密码加解密权限完全交还给用户。
- **开源防呆设计**：真实配置文件名 `config.yaml` 已被严格列入 `.gitignore`。代码库内仅提供脱敏的 `config.example.yaml` 供参考，最大程度杜绝了开发者误传真实服务器 IP 和密码的事故。

## ⚡ 硬件加速与优化

- **Native Crypto**：已内置 `target-cpu=native` 配置，全面激活 Apple Silicon (M1/M2/M3) Crypto 扩展或 Intel/AMD AES-NI 硬件加密加速，加解密开销降低 80% 以上。
- **流媒体优化**：为高码率流媒体（如 YouTube 1080P/4K/8K）提供底层的多路复用与大文件传输优化，利用 OS 默认 TCP 缓冲机制取代传统 Nagle 算法，稳定跑满物理带宽。
- **全域性能解放**：我们在 `Cargo.toml` 中强制注入了 `[profile.dev] opt-level = 3`。无论是您进行日常 Debug 开发，还是使用 `LTO` 极限编译构建 Release 产物，均能享受顶配的加解密吞吐率。

## 🛠️ 技术栈

- **前端界面**：[Vue 3](https://vuejs.org/) + [TypeScript](https://www.typescriptlang.org/) + [Vite](https://vitejs.dev/)
- **应用框架**：[Tauri 2](https://v2.tauri.app/)
- **核心网络**：[Rust](https://www.rust-lang.org/) + [Tokio](https://tokio.rs/) + [Russh](https://github.com/warp-tech/russh)
- **命令行工具**：[Clap](https://docs.rs/clap/) + [Env Logger](https://docs.rs/env_logger/)

## 📝 目录结构

- `apps/desktop/` - 面向日常用户的 Tauri 客户端与 Vue 图形化前端源码。
- `crates/core/` - OxiTun 的最强心脏：Rust 核心代理层 (涵盖网络协议栈、AES加密、系统代理挂载、智能路由引擎)。
- `crates/cli/` - 面向硬核极客与服务器环境的极简纯命令行工具（构建物极小，不含任何前端冗余）。
- `configs/` - 脱敏后的配置文件参考模板 (`config.example.yaml`)。

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
