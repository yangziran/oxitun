#!/usr/bin/env bash
# OxiTun 可复现基准测试骨架
#
# 前置条件：
#   1. 一台可达的 SSH 服务器（建议与客户端在不同网络，便于测真实隧道性能）
#   2. 已按 configs/config.yaml 配置并启动 oxitun-cli（SOCKS5 监听默认 127.0.0.1:1080）
#
# 用法：
#   ./scripts/bench.sh [SOCKS5_ADDR] [TEST_URL]
# 示例：
#   ./scripts/bench.sh 127.0.0.1:1080 https://speed.cloudflare.com/__down?bytes=104857600
#
# 指标：吞吐（下载 100MB 耗时）、首包延迟（TTFB）、并发连接成功率。
# 对比方法：分别配置 pool_size = 1 / 8 / 16 重启后各跑一轮；如需对照 Gotun，
# 用相同服务器、相同 URL 在 gotun 的 dynamic 隧道上重复本脚本。

set -euo pipefail
SOCKS="${1:-127.0.0.1:1080}"
URL="${2:-https://speed.cloudflare.com/__down?bytes=104857600}"

echo "== 代理: $SOCKS  目标: $URL =="

echo "-- 首包延迟 (TTFB, 5 次) --"
for i in 1 2 3 4 5; do
  curl -x "socks5://$SOCKS" -o /dev/null -s \
    -w "  第${i}次: TTFB=%{time_starttransfer}s 总耗时=%{time_total}s\n" "$URL" --max-time 30 -r 0-0
done

echo "-- 吞吐 (下载约 100MB) --"
curl -x "socks5://$SOCKS" -o /dev/null -s \
  -w "  总耗时=%{time_total}s  平均速度=%{speed_download} B/s\n" "$URL" --max-time 300

echo "-- 并发连接 (50 并发小请求) --"
fail=0
for i in $(seq 1 50); do
  curl -x "socks5://$SOCKS" -o /dev/null -s --max-time 20 -r 0-1023 "$URL" &
done > /dev/null
for job in $(jobs -p); do
  wait "$job" || fail=$((fail + 1))
done
echo "  失败数: $fail / 50"

echo "== 完成。记录本机内存占用（ps -o rss= -p \$(pgrep -f oxitun)）作为内存指标 =="
