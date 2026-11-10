# OxiTun Makefile
# 单一来源版本取自 Cargo.toml [workspace.package]，由 scripts/check-version.sh 保证与 GUI 一致

APP_NAME_CLI = oxitun-cli
BUILD_DIR = bin
CLI_PKG = oxitun-cli
GUI_DIR = apps/desktop

# 从 workspace 根 Cargo.toml 提取版本（供说明性输出使用）
VERSION := $(shell grep -A2 '^\[workspace.package\]' Cargo.toml | grep '^version' | sed 's/.*"\(.*\)"/\1/')

.PHONY: all clean check-version \
        build-cli build-cli-mac build-cli-linux build-cli-win \
        build-gui build-gui-mac build-gui-linux build-gui-win \
        build release bench

all: check-version build-cli build-gui

check-version:
	@bash scripts/check-version.sh

# ---------------- CLI（服务端/软路由/无界面） ----------------

# 当前平台（开发用）
build-cli: check-version
	@echo "Building oxitun-cli v$(VERSION) for current platform..."
	@mkdir -p $(BUILD_DIR)
	@cargo build -p $(CLI_PKG) --release
	@cp "target/release/$(APP_NAME_CLI)$(shell [ "$(OS)" = "Windows_NT" ] && echo .exe)" "$(BUILD_DIR)/$(APP_NAME_CLI)$(shell [ "$(OS)" = "Windows_NT" ] && echo .exe)"
	@echo "完成：$(BUILD_DIR)/$(APP_NAME_CLI)"

# macOS（amd64 + arm64，交叉或本机）
build-cli-mac: check-version
	@echo "Building oxitun-cli for macOS (amd64 & arm64)..."
	@mkdir -p $(BUILD_DIR)
	@rustup target add x86_64-apple-darwin aarch64-apple-darwin 2>/dev/null || true
	@cargo build -p $(CLI_PKG) --release --target x86_64-apple-darwin
	@cargo build -p $(CLI_PKG) --release --target aarch64-apple-darwin
	@cp target/x86_64-apple-darwin/release/$(APP_NAME_CLI) $(BUILD_DIR)/$(APP_NAME_CLI)-macos-amd64
	@cp target/aarch64-apple-darwin/release/$(APP_NAME_CLI) $(BUILD_DIR)/$(APP_NAME_CLI)-macos-arm64
	@echo "完成：$(BUILD_DIR)/$(APP_NAME_CLI)-macos-{amd64,arm64}"

# Linux（amd64 + arm64，musl 静态链接；需对应 target）
build-cli-linux: check-version
	@echo "Building oxitun-cli for Linux (amd64 & arm64, musl static)..."
	@mkdir -p $(BUILD_DIR)
	@rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl 2>/dev/null || true
	@cargo build -p $(CLI_PKG) --release --target x86_64-unknown-linux-musl
	@cargo build -p $(CLI_PKG) --release --target aarch64-unknown-linux-musl
	@cp target/x86_64-unknown-linux-musl/release/$(APP_NAME_CLI) $(BUILD_DIR)/$(APP_NAME_CLI)-linux-amd64
	@cp target/aarch64-unknown-linux-musl/release/$(APP_NAME_CLI) $(BUILD_DIR)/$(APP_NAME_CLI)-linux-arm64
	@echo "完成：$(BUILD_DIR)/$(APP_NAME_CLI)-linux-{amd64,arm64}"

# Windows（amd64；需 windows 目标链）
build-cli-win: check-version
	@echo "Building oxitun-cli for Windows (amd64)..."
	@mkdir -p $(BUILD_DIR)
	@rustup target add x86_64-pc-windows-msvc 2>/dev/null || true
	@cargo build -p $(CLI_PKG) --release --target x86_64-pc-windows-msvc
	@cp target/x86_64-pc-windows-msvc/release/$(APP_NAME_CLI).exe $(BUILD_DIR)/$(APP_NAME_CLI)-windows-amd64.exe
	@echo "完成：$(BUILD_DIR)/$(APP_NAME_CLI)-windows-amd64.exe"

# ---------------- GUI（桌面端，Tauri） ----------------

# 当前平台（开发用）
build-gui: check-version
	@echo "Building OxiTun GUI v$(VERSION) for current platform..."
	@cd $(GUI_DIR) && npm install && npm run tauri build

# GUI 产物目录（src-tauri 是 workspace 成员，Tauri 输出在 workspace 根 target/ 下）
GUI_BUNDLE_DIR = target/release/bundle

# GUI 各平台需在本机/CI 对应平台构建（Tauri 依赖平台 SDK）。
# 这些 target 仅作提示：实际仍构建宿主平台，并校验宿主以免误产错误平台的包。
build-gui-mac: check-version
	@[ "$$(uname -s)" = "Darwin" ] || { echo "ERROR: build-gui-mac 需在 macOS 上运行"; exit 1; }
	@$(MAKE) build-gui
	@echo "macOS 包位于 $(GUI_BUNDLE_DIR)/"

build-gui-linux: check-version
	@[ "$$(uname -s)" = "Linux" ] || { echo "ERROR: build-gui-linux 需在 Linux 上运行"; exit 1; }
	@$(MAKE) build-gui
	@echo "Linux 包位于 $(GUI_BUNDLE_DIR)/"

build-gui-win: check-version
	@[ "$$OS" = "Windows_NT" ] || { echo "ERROR: build-gui-win 需在 Windows 上运行"; exit 1; }
	@$(MAKE) build-gui
	@echo "Windows 包位于 $(GUI_BUNDLE_DIR)/"

# ---------------- 组合与工具 ----------------

# 本机全部（CLI + GUI）
build: build-cli build-gui

# 基准测试（吞吐/TTFB/并发）
bench:
	@bash scripts/bench.sh

# 发布前检查（版本一致性 + 测试 + lint）
release: check-version
	@cargo fmt --all -- --check
	@cargo clippy --workspace --all-targets -- -D warnings
	@cargo test --workspace
	@cd $(GUI_DIR) && npx vue-tsc --noEmit
	@echo "✅ 发布检查通过，可打 tag 触发 CI 打包"

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@cargo clean
	@rm -rf $(GUI_DIR)/node_modules $(GUI_DIR)/dist
	@echo "完成"
