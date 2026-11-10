#!/usr/bin/env bash
# 版本一致性检查：Cargo workspace 与 tauri.conf.json / package.json / package-lock.json 必须一致
set -euo pipefail
cd "$(dirname "$0")/.."

WS=$(grep -A2 '^\[workspace.package\]' Cargo.toml | grep '^version' | sed 's/.*"\(.*\)"/\1/')
TAURI=$(grep '"version"' apps/desktop/src-tauri/tauri.conf.json | head -1 | sed 's/.*"\(.*\)".*/\1/')
PKG=$(grep '"version"' apps/desktop/package.json | head -1 | sed 's/.*"\(.*\)".*/\1/')
LOCK=$(grep '"version"' apps/desktop/package-lock.json | head -1 | sed 's/.*"\(.*\)".*/\1/')

echo "workspace=$WS tauri.conf=$TAURI package.json=$PKG package-lock.json=$LOCK"
if [ "$WS" != "$TAURI" ] || [ "$WS" != "$PKG" ] || [ "$PKG" != "$LOCK" ]; then
  echo "ERROR: 版本号不一致，请以 Cargo.toml [workspace.package] 为准统一四处" >&2
  exit 1
fi

# workspace 成员必须使用 version.workspace = true，禁止成员硬编码独立版本
if grep -rl '^version *= *"' crates/*/Cargo.toml apps/desktop/src-tauri/Cargo.toml 2>/dev/null | grep -q .; then
  echo "ERROR: 以下成员 crate 硬编码了独立版本，应改为 version.workspace = true：" >&2
  grep -rl '^version *= *"' crates/*/Cargo.toml apps/desktop/src-tauri/Cargo.toml 2>/dev/null >&2
  exit 1
fi
echo "版本一致: $WS"
