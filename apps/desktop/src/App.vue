<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { isEnabled, enable, disable } from '@tauri-apps/plugin-autostart';

interface ServerConfig {
  name: string;
  host: string;
  port: number;
  user: string;
  auth_type?: string;
  password?: string;
  key_path?: string;
  pool_size: number;
  keep_alive_interval: number;
  timeout_seconds: number;
  strict_host_key: boolean;
  host_key?: string;
  encrypted?: boolean;
  jump_host?: string;
}

interface TunnelConfig {
  name: string;
  server_names: string[];
  type: "local" | "dynamic" | "remote" | "dns" | "dns_dot" | "dns_doh";
  port: number;
  remote_addr?: string;
  share_on_lan: boolean;
  strategy?: "failover" | "round_robin";
}

interface Config {
  general: {
    auto_startup: boolean;
    auto_set_system_proxy: boolean;
    auto_connect?: boolean;
    pin_window?: boolean;
    chnroute_update_interval_hours?: number;
    chnroute_url: string;
    metrics_addr?: string;
  };
  servers: ServerConfig[];
  tunnels: TunnelConfig[];
  routing: {
    mode: "global" | "whitelist" | "blacklist" | "direct";
    bypass_lan: boolean;
    whitelist: string[];
    blacklist: string[];
  };
}

const config = ref<Config>({
  general: { auto_startup: false, auto_set_system_proxy: false, auto_connect: false, pin_window: false, chnroute_update_interval_hours: 24, chnroute_url: "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt" },
  servers: [],
  tunnels: [],
  routing: { mode: "global", bypass_lan: true, whitelist: [], blacklist: [] }
});

const currentTab = ref("general");
const isRunning = ref(false);
const isStarting = ref(false);
const startError = ref("");
const hostKeyChangedTarget = ref<{ host: string; port: number } | null>(null);
// ===== 分层反馈：toast 轻提示 + 确认模态 + 内联错误 =====
interface Toast { id: number; type: "success" | "error" | "info"; text: string }
const toasts = ref<Toast[]>([]);
let toastSeq = 0;
function toast(type: Toast["type"], text: string) {
  const id = ++toastSeq;
  toasts.value.push({ id, type, text });
  setTimeout(() => { toasts.value = toasts.value.filter(t => t.id !== id); }, type === "error" ? 6000 : 3000);
}

// 删除等破坏性操作的二次确认模态
const confirmState = ref<{ text: string; resolve?: (ok: boolean) => void } | null>(null);
function askConfirm(text: string): Promise<boolean> {
  return new Promise(res => { confirmState.value = { text, resolve: res }; });
}
function answerConfirm(ok: boolean) {
  confirmState.value?.resolve?.(ok);
  confirmState.value = null;
}

// ===== 诊断页：日志 + 指标 + 测试结果 =====
interface LogEntry { time: string; level: string; message: string }
interface MetricsSnapshot { active_connections: number; bytes_tx: number; bytes_rx: number; ssh_pool_rebuilds: number; ssh_reconnects: number }
const diagLogs = ref<LogEntry[]>([]);
const diagMetrics = ref<MetricsSnapshot | null>(null);
let diagTimer: ReturnType<typeof setInterval> | null = null;

async function refreshDiagnostics() {
  try {
    diagLogs.value = await invoke<LogEntry[]>("get_logs");
    diagMetrics.value = await invoke<MetricsSnapshot>("get_metrics");
  } catch (e) { /* 忽略瞬时错误 */ }
}

async function clearDiagLogs() {
  await invoke("clear_logs");
  diagLogs.value = [];
}

watch(currentTab, (tab: string) => {
  if (tab === "diagnostics") {
    refreshDiagnostics();
    diagTimer = setInterval(refreshDiagnostics, 1000);
  } else if (diagTimer) {
    clearInterval(diagTimer);
    diagTimer = null;
  }
});

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// 状态胶囊：区分过渡态与终态
const statusClass = computed(() =>
  isStarting.value ? "transitioning" : (startError.value && !isRunning.value ? "error" : (isRunning.value ? "running" : "stopped"))
);
const statusText = computed(() =>
  isStarting.value ? "启动中…" : (startError.value && !isRunning.value ? "启动失败" : (isRunning.value ? "已开启" : "已关闭"))
);
const selectedServerIdx = ref(0);
const advancedExpanded = ref(false);

// ===== 主机密钥首次确认（TOFU）=====
interface PendingHostKey {
  host: string;
  port: number;
  key_type: string;
  fingerprint: string;
}
const pendingHostKey = ref<PendingHostKey | null>(null);

async function resolveHostKey(accept: boolean) {
  const pending = pendingHostKey.value;
  if (!pending) return;
  try {
    await invoke("resolve_host_key", { host: pending.host, port: pending.port, accept });
  } catch (e) {
    // 确认已过期等情况：直接关闭弹窗
  }
  pendingHostKey.value = null;
}



function selectServer(idx: number) {
  selectedServerIdx.value = idx;
  advancedExpanded.value = false;
}








const whitelistText = computed({
  get: () => config.value.routing.whitelist.join('\n'),
  set: (val) => { config.value.routing.whitelist = val.split('\n').map(s => s.trim()).filter(s => s.length > 0); }
});
const blacklistText = computed({
  get: () => config.value.routing.blacklist.join('\n'),
  set: (val) => { config.value.routing.blacklist = val.split('\n').map(s => s.trim()).filter(s => s.length > 0); }
});

onMounted(async () => {
  try {
    await loadConfig();
    isRunning.value = await invoke("get_running_state");
    
    try {
      config.value.general.auto_startup = await isEnabled();
    } catch(e) {}
    
    try {
      await getCurrentWindow().setAlwaysOnTop(!!config.value.general.pin_window);
    } catch(e) {}
    
    listen('state-changed', async () => {
      try {
        await loadConfig();
        isRunning.value = await invoke("get_running_state");
      } catch(e) {}
    });
    listen<string>('config-save-error', (event) => {
      toast("error", event.payload);
    });

    // 主机密钥首次确认事件（后端发起，弹模态等待用户决策）
    listen<PendingHostKey>('host-key-verify', (event) => {
      pendingHostKey.value = event.payload;
    });
    // 窗口刚打开时补拉待确认请求（事件可能先于监听注册发出）
    try {
      const pendings = await invoke<PendingHostKey[]>("get_pending_host_keys");
      if (pendings.length > 0) pendingHostKey.value = pendings[0];
    } catch(e) {}
    
    getCurrentWindow().onFocusChanged(async ({ payload: focused }) => {
      if (focused) {
        try {
          await loadConfig();
          isRunning.value = await invoke("get_running_state");
        } catch(e) {}
      }
    });
  } catch (e: any) {
    toast("error", `初始化错误: ${String(e)}`);
  }
});

async function loadConfig() {
  try {
    const res = await invoke<Config>("get_config");
    
    for (let srv of res.servers) {
      if (!srv.auth_type) srv.auth_type = srv.key_path?.trim() ? "key" : "password";
      if (srv.pool_size === undefined) srv.pool_size = 8;
      if (srv.timeout_seconds === undefined) srv.timeout_seconds = 15;
    }
    
    if (res.tunnels && res.tunnels.length > 0 && res.tunnels[0].server_names && res.tunnels[0].server_names.length === 0 && res.servers && res.servers.length > 0) {
      res.tunnels[0].server_names = [res.servers[0].name];
    }
    config.value = res;
  } catch (e) {
    toast("error", "加载配置失败");
  }
}

// ===== 表单字段级校验：保存前整批检查，问题定位到具体条目 =====
function validateConfig(): string | null {
  const seenServers = new Set<string>();
  for (const srv of config.value.servers) {
    if (!srv.name?.trim()) return "存在未命名的节点，请先在「节点管理」填写节点名称";
    if (seenServers.has(srv.name)) return `节点名称「${srv.name}」重复，请改名后再保存`;
    seenServers.add(srv.name);
    if (!srv.host?.trim()) return `节点「${srv.name}」的服务器地址不能为空`;
    if (!Number.isInteger(srv.port) || srv.port < 1 || srv.port > 65535)
      return `节点「${srv.name}」的端口需在 1-65535 之间`;
  }
  const seenTunnels = new Set<string>();
  for (const tun of config.value.tunnels) {
    if (!tun.name?.trim()) return "存在未命名的规则，请先填写规则名称";
    if (seenTunnels.has(tun.name)) return `规则名称「${tun.name}」重复，请改名后再保存`;
    seenTunnels.add(tun.name);
    if (!Number.isInteger(tun.port) || tun.port < 1 || tun.port > 65535)
      return `规则「${tun.name}」的监听端口需在 1-65535 之间`;
  }
  return null;
}

async function saveConfig() {
  const err = validateConfig();
  if (err) { toast("error", err); return; }
  try {
    await invoke("save_config", { newConfig: config.value });
    toast("success", "配置已保存");
  } catch (e) {
    toast("error", `保存失败: ${e}`);
  }
}

async function toggleAutostart() {
  if (config.value.general.auto_startup) {
    await enable();
  } else {
    await disable();
  }
  await saveConfig();
}

async function togglePin() {
  await saveConfig();
  await getCurrentWindow().setAlwaysOnTop(!!config.value.general.pin_window);
}

function isHostKeyChangedError(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes("key changed") || message.includes("主机密钥发生变化") || message.includes("主机密钥变更");
}

async function recoverChangedHostKey() {
  const target = hostKeyChangedTarget.value;
  if (!target || isStarting.value) return;
  const confirmed = await askConfirm(
    `确定清除 ${target.host}:${target.port} 的旧主机密钥信任并重新连接吗？如果未确认服务器密钥已合法更换，继续连接可能遭受中间人攻击。`
  );
  if (!confirmed) return;

  try {
    await invoke("remove_known_host", { host: target.host, port: target.port });
  } catch (e) {
    hostKeyChangedTarget.value = null;
    startError.value = `清除旧主机密钥信任失败: ${e}`;
    toast("error", startError.value);
    return;
  }
  await toggleProxy();
}

async function toggleProxy() {
  if (isStarting.value) return;
  startError.value = "";
  hostKeyChangedTarget.value = null;
  isStarting.value = true;

  try {
    if (isRunning.value) {
      await invoke("stop_tunnels");
      isRunning.value = false;
    } else {
      let firstServer: ServerConfig | undefined;
      try {
        if (config.value.servers.length === 0) {
          // 新手引导：跳转到节点管理页而非打断式报错
          toast("info", "请先在「节点管理」中添加至少一个服务器节点");
          currentTab.value = "servers";
          return;
        }
        if (config.value.tunnels.length === 0) {
          config.value.tunnels.push({
            name: "SOCKS5 代理",
            server_names: [config.value.servers[0].name],
            type: "dynamic",
            port: 10808,
            share_on_lan: false
          });
          await saveConfig();
        }

        const firstServerName = config.value.tunnels[0]?.server_names[0];
        firstServer = config.value.servers.find(s => s.name === firstServerName) ?? config.value.servers[0];
        await invoke("start_tunnels");
        isRunning.value = true;
      } catch(e) {
        // 内联错误（启动区持续可见）+ toast 瞬时提示
        startError.value = String(e);
        if (firstServer && isHostKeyChangedError(startError.value)) {
          hostKeyChangedTarget.value = { host: firstServer.host, port: firstServer.port };
        }
        toast("error", `开启代理失败: ${e}`);
      }
    }
  } finally {
    isStarting.value = false;
  }
}

function addTunnel() {
  let n = config.value.tunnels.length;
  while (config.value.tunnels.some(t => t.name === `新监听器 ${n}`)) n++;
  config.value.tunnels.push({
    name: `新监听器 ${n}`,
    server_names: [config.value.servers.length > 0 ? config.value.servers[0].name : ""],
    type: "local",
    port: 8080,
    remote_addr: "127.0.0.1:80",
    share_on_lan: false
  });
  saveConfig();
}

async function removeTunnel(index: number) {
  const name = config.value.tunnels[index]?.name ?? "";
  if (!await askConfirm(`确定删除规则「${name}」吗？`)) return;
  config.value.tunnels.splice(index, 1);
  saveConfig();
}

const isTesting = ref(false);
// 测试结果持久展示，诊断页也会读取
const lastTestResult = ref<{ server: string; ok: boolean; text: string } | null>(null);

async function testConnection(serverName: string) {
  if (isTesting.value) return;
  isTesting.value = true;
  toast("info", "正在测试连接...");
  try {
    await saveConfig();
    const result = await invoke<string>("test_ssh_connection", { serverName });
    lastTestResult.value = { server: serverName, ok: true, text: String(result) };
    toast("success", String(result));
  } catch (e: any) {
    lastTestResult.value = { server: serverName, ok: false, text: String(e) };
    toast("error", `测试失败: ${String(e)}`);
  } finally {
    isTesting.value = false;
  }
}

function addServer() {
  let n = config.value.servers.length + 1;
  while (config.value.servers.some(s => s.name === `节点 ${n}`)) n++;
  const newName = `节点 ${n}`;
  config.value.servers.push({
    name: newName, host: "127.0.0.1", port: 22, user: "root", pool_size: 8, keep_alive_interval: 3,
    timeout_seconds: 15, strict_host_key: true, auth_type: "password"
  });
  selectedServerIdx.value = config.value.servers.length - 1; advancedExpanded.value = false;
}

async function removeServer(index: number) {
  if (index < 0 || index >= config.value.servers.length) return;
  const name = config.value.servers[index]?.name ?? "";
  if (!await askConfirm(`确定删除节点「${name}」吗？引用它的隧道将不可用。`)) return;
  config.value.servers.splice(index, 1);
  if (selectedServerIdx.value >= config.value.servers.length) {
    selectedServerIdx.value = config.value.servers.length - 1; advancedExpanded.value = false;
  }
  saveConfig();
}



</script>

<template>
  <div class="mac-window">
    <div class="toolbar">
      <div class="tab" :class="{ active: currentTab === 'general' }" @click="currentTab = 'general'">
        <span>系统状态</span>
      </div>
      <div class="tab" :class="{ active: currentTab === 'servers' }" @click="currentTab = 'servers'">
        <span>节点管理</span>
      </div>
      <div class="tab" :class="{ active: currentTab === 'routing' }" @click="currentTab = 'routing'">
        <span>路由与分流</span>
      </div>
      <div class="tab" :class="{ active: currentTab === 'diagnostics' }" @click="currentTab = 'diagnostics'">
        <span>诊断</span>
      </div>
    </div>
    <div class="content" :class="{ 'no-padding': currentTab === 'servers' }">
      <!-- General Tab -->
      <div v-show="currentTab === 'general'" class="tab-pane">
        
        <div class="settings-group mac-list-group">
          <h3 class="group-title">基础设置</h3>
          
          <div class="mac-row">
            <label>当前状态</label>
            <div class="control" style="justify-content: space-between; width: 100%;">
              <span class="status-pill" :class="statusClass">
                <span class="status-dot"></span>{{ statusText }}
              </span>
              <button :class="isRunning ? '' : 'primary-btn'" @click="toggleProxy" :disabled="isStarting" style="padding: 4px 12px; font-size: 12px;">
                {{ isStarting ? "..." : (isRunning ? "停止代理" : "开启主代理") }}
              </button>
            </div>
          </div>
          <div v-if="startError && !isRunning" class="mac-row">
            <label></label>
            <div class="control" style="color: var(--danger); font-size: 12px; gap: 12px;">
              <span>{{ startError }}</span>
              <button v-if="hostKeyChangedTarget" @click="recoverChangedHostKey" :disabled="isStarting" style="flex-shrink: 0; padding: 4px 10px; font-size: 12px;">清除旧信任并重新连接</button>
            </div>
          </div>
          
          <div class="mac-row">
            <label>开机时自动启动</label>
            <div class="control" style="justify-content: flex-end;">
              <input type="checkbox" v-model="config.general.auto_startup" @change="toggleAutostart" />
            </div>
          </div>

          <div class="mac-row">
            <label>自动启动主代理</label>
            <div class="control" style="justify-content: flex-end;">
              <input type="checkbox" v-model="config.general.auto_connect" @change="saveConfig" />
            </div>
          </div>

          <div class="mac-row">
            <label>接管系统代理</label>
            <div class="control" style="justify-content: space-between; gap: 12px;">
              <span style="font-size: 11px; color: var(--muted);">开启主代理时自动设置系统 SOCKS5 代理，停止后自动还原</span>
              <input type="checkbox" v-model="config.general.auto_set_system_proxy" @change="saveConfig" style="flex-shrink: 0;" />
            </div>
          </div>

          <div class="mac-row">
            <label>保持窗口置顶</label>
            <div class="control" style="justify-content: flex-end;">
              <input type="checkbox" v-model="config.general.pin_window" @change="togglePin" />
            </div>
          </div>
        </div>

        <div class="settings-group mac-list-group" v-if="config.tunnels.length > 0">
          <h3 class="group-title">主代理</h3>
          
          <div class="mac-row" style="border-bottom: none; padding-bottom: 0; padding-top: 8px;">
            <div class="control" style="width: 100%; display: flex; gap: 8px; align-items: center; justify-content: center;">
              <select v-model="config.tunnels[0].type" @change="saveConfig" style="width: 120px; flex-shrink: 0; text-align: center;">
                <option value="dynamic">动态代理 (SOCKS5)</option>
                <option value="local">本地端口转发 (Local)</option>
                <option value="remote">远程反向转发 (Remote)</option>
                <option value="dns">DNS 代理 (UDP 转 TCP)</option>
                <option value="dns_dot">DNS 代理 (DoT)</option>
                <option value="dns_doh">DNS 代理 (DoH)</option>
              </select>
              
              <select :key="config.tunnels[0].server_names[0]" v-model="config.tunnels[0].server_names[0]" @change="saveConfig" style="width: 200px; flex-shrink: 0;">
                <option v-for="srv in config.servers" :key="srv.name" :value="srv.name">{{ srv.name }}</option>
              </select>
              
              <span style="font-weight: 500;">:</span>
              
              <input type="number" v-model.number="config.tunnels[0].port" placeholder="1080" @blur="saveConfig" style="width: 70px; flex-shrink: 0; text-align: center;" />
            </div>
          </div>
          
          <div class="mac-row" v-if="['local', 'remote', 'dns', 'dns_dot', 'dns_doh'].includes(config.tunnels[0].type)" style="border-bottom: none; padding-top: 12px; padding-bottom: 8px;">
            <div class="control" style="width: 100%; display: flex; gap: 8px; align-items: center; justify-content: center;">
              <span style="font-size: 13px; color: var(--text); white-space: nowrap;">{{ ['dns', 'dns_dot', 'dns_doh'].includes(config.tunnels[0].type) ? '上游 DNS:' : '目标地址:' }}</span>
              <input v-model="config.tunnels[0].remote_addr" placeholder="例如: 192.168.1.1:80" @blur="saveConfig" style="width: 200px; text-align: center;" />
            </div>
          </div>
          
          <div class="mac-row" style="padding-top: 8px; padding-bottom: 8px;">
            <div class="control" style="justify-content: center; gap: 8px; width: 100%; align-items: center;">
              <input type="checkbox" v-model="config.tunnels[0].share_on_lan" @change="saveConfig" style="margin: 0;" />
              <span style="font-size: 13px; color: var(--text);">允许局域网连接</span>
            </div>
          </div>
        </div>

        <div class="settings-group mac-list-group" style="padding-bottom: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 class="group-title" style="margin: 0; border: none; padding: 0;">自定义规则</h3>
            <button class="add-btn" @click="addTunnel" style="padding: 4px 8px; font-size: 12px;">＋ 添加规则</button>
          </div>
          
          <div class="tunnel-list" style="gap: 16px;">
            <template v-for="(tun, idx) in config.tunnels" :key="idx">
              <div v-if="idx > 0" class="tunnel-card" style="background: var(--surface-soft); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border-soft);">
                <div style="display: flex; justify-content: space-between; margin-bottom: 12px; border-bottom: 1px solid var(--border-soft); padding-bottom: 8px;">
                  <div style="font-weight: 600; font-size: 13px; color: var(--text);">扩展规则 {{ idx }}</div>
                  <button class="icon-btn" @click="removeTunnel(idx)" style="color: var(--danger); background: none; border: none; cursor: pointer; padding: 0; font-size: 12px;">删除规则</button>
                </div>
                
                <div class="mac-row" style="border-bottom: none; padding-bottom: 0; padding-top: 4px;">
                  <div class="control" style="width: 100%; display: flex; gap: 8px; align-items: center; justify-content: center;">
                    <select v-model="tun.type" @change="saveConfig" style="width: 120px; flex-shrink: 0; text-align: center;">
                      <option value="dynamic">动态代理 (SOCKS5)</option>
                      <option value="local">本地端口转发 (Local)</option>
                      <option value="remote">远程反向转发 (Remote)</option>
                      <option value="dns">DNS 代理 (UDP 转 TCP)</option>
                      <option value="dns_dot">DNS 代理 (DoT)</option>
                      <option value="dns_doh">DNS 代理 (DoH)</option>
                    </select>
                    
                    <select :key="tun.server_names && tun.server_names.length > 0 ? tun.server_names[0] : 'empty'" :value="tun.server_names && tun.server_names.length > 0 ? tun.server_names[0] : ''" @change="(e: any) => { tun.server_names = e.target.value ? [e.target.value] : []; saveConfig(); }" style="width: 200px; flex-shrink: 0;">
                      <option value="">(跟随状态栏主节点)</option>
                      <option v-for="srv in config.servers" :key="srv.name" :value="srv.name">{{ srv.name }}</option>
                    </select>
                    
                    <span style="font-weight: 500;">:</span>
                    
                    <input type="number" v-model.number="tun.port" placeholder="1080" @blur="saveConfig" style="width: 70px; flex-shrink: 0; text-align: center;" />
                  </div>
                </div>
                
                <div class="mac-row" v-if="['local', 'remote', 'dns', 'dns_dot', 'dns_doh'].includes(tun.type)" style="border-bottom: none; padding-top: 12px; padding-bottom: 4px;">
                  <div class="control" style="width: 100%; display: flex; gap: 8px; align-items: center; justify-content: center;">
                    <span style="font-size: 13px; color: var(--text); white-space: nowrap;">{{ ['dns', 'dns_dot', 'dns_doh'].includes(tun.type) ? '上游 DNS:' : '目标地址:' }}</span>
                    <input v-model="tun.remote_addr" :placeholder="['dns_dot', 'dns_doh'].includes(tun.type) ? '例如: dot.pub 或 doh.pub:443' : (tun.type === 'dns' ? '例如: 8.8.8.8:53' : '例如: 192.168.1.1:80')" @blur="saveConfig" style="width: 200px; text-align: center;" />
                  </div>
                </div>
                
                <div class="mac-row" style="padding-top: 8px; padding-bottom: 4px;">
                  <div class="control" style="justify-content: center; gap: 8px; width: 100%; align-items: center;">
                    <input type="checkbox" v-model="tun.share_on_lan" @change="saveConfig" style="margin: 0;" />
                    <span style="font-size: 13px; color: var(--text);">允许局域网连接</span>
                  </div>
                </div>
              </div>
            </template>
            <div v-if="config.tunnels.length <= 1" class="empty-hero">
              <div class="hero-icon">🔀</div>
              <div class="hero-title">暂无自定义规则</div>
              <div class="hero-desc">除主代理外，还可以为不同用途添加独立的端口转发或 DNS 代理规则。</div>
              <button class="hero-cta" @click="addTunnel">＋ 添加规则</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Servers Tab -->
      <div v-show="currentTab === 'servers'" class="master-detail">
        <div class="master-list">
          <div class="servers-scroll">
            <div
              v-for="(srv, idx) in config.servers" :key="srv.name"
              class="server-row"
              :class="{ 'server-active': selectedServerIdx === idx }"
              @click="selectServer(idx)"
            >
              <div class="srv-title">{{ srv.name }}</div>
              <div class="srv-sub">{{ srv.user || 'root' }}@{{ srv.host }}:{{ srv.port }}</div>
            </div>
            <!-- 空态引导：图标 + 结论 + 解释 + CTA -->
            <div v-if="config.servers.length === 0" class="empty-hero">
              <div class="hero-icon">🖥️</div>
              <div class="hero-title">还没有服务器节点</div>
              <div class="hero-desc">添加一个 SSH 服务器后即可开启代理，所有隧道都通过它转发流量。</div>
              <button class="hero-cta" @click="addServer">＋ 添加节点</button>
            </div>
          </div>
          <div class="servers-toolbar">
            <button class="icon-btn" @click="addServer" title="添加节点">＋</button>
            <button class="icon-btn" @click="removeServer(selectedServerIdx)" :disabled="selectedServerIdx < 0 || selectedServerIdx >= config.servers.length" title="删除节点">－</button>
            <div class="spacer"></div>
            <span style="font-size: 11px; color: var(--muted); margin-right: 8px;">共 {{ config.servers.length }} 个节点</span>
          </div>
        </div>
        
        <div class="detail-view">
          <div v-if="config.servers.length > 0 && selectedServerIdx >= 0 && selectedServerIdx < config.servers.length" class="detail-scroll">
            
            <div class="settings-group mac-list-group">
              <h3 class="group-title">基础配置</h3>
              
              <div class="mac-row">
                <label>节点名称</label>
                <div class="control">
                  <input v-model="config.servers[selectedServerIdx].name" placeholder="例如: 日本节点 01" @blur="saveConfig" />
                </div>
              </div>
              
              <div class="mac-row">
                <label>服务器 (IP:端口)</label>
                <div class="control" style="gap: 8px; max-width: 280px; width: 100%;">
                  <input v-model="config.servers[selectedServerIdx].host" placeholder="IP 或 域名" @blur="saveConfig" style="flex: 1;" />
                  <span>:</span>
                  <input type="number" v-model.number="config.servers[selectedServerIdx].port" class="short-input" style="width: 70px;" @blur="saveConfig" />
                </div>
              </div>

              <div class="mac-row">
                <label>登录用户</label>
                <div class="control">
                  <input v-model="config.servers[selectedServerIdx].user" placeholder="root" @blur="saveConfig" />
                </div>
              </div>

              <div class="mac-row">
                <label>身份验证</label>
                <div class="control" style="gap: 8px; max-width: 300px; width: 100%;">
                  <select v-model="config.servers[selectedServerIdx].auth_type" @change="saveConfig" style="width: 100px; flex-shrink: 0;">
                    <option value="password">密码</option>
                    <option value="key">私钥</option>
                  </select>
                  
                  <input v-if="config.servers[selectedServerIdx].auth_type === 'password'"
                         type="password" v-model="config.servers[selectedServerIdx].password" 
                         placeholder="输入登录密码" @blur="saveConfig" style="flex: 1;" />
                         
                  <input v-else 
                         v-model="config.servers[selectedServerIdx].key_path" 
                         placeholder="例如: ~/.ssh/id_rsa" @blur="saveConfig" style="flex: 1;" />
                </div>
              </div>

              <div style="margin: 12px 0;">
                <button class="primary-btn" @click="testConnection(config.servers[selectedServerIdx].name)" :disabled="isTesting" style="background: var(--success); width: 100%;">
                  {{ isTesting ? "测试中..." : "保存并测试" }}
                </button>
              </div>
            </div>

            <div class="settings-group mac-list-group">
              <div style="display: flex; justify-content: space-between; align-items: center; cursor: pointer; padding: 4px 0;" @click="advancedExpanded = !advancedExpanded">
                <h3 class="group-title" style="margin: 0; border: none; padding: 0;">高级配置</h3>
                <span style="color: var(--muted); font-size: 12px; font-weight: 500; background: var(--hover); padding: 4px 8px; border-radius: 4px;">{{ advancedExpanded ? '▲ 收起' : '▼ 展开' }}</span>
              </div>
              
              <div v-show="advancedExpanded" style="margin-top: 12px; border-top: 1px solid var(--hover); padding-top: 8px;">
                
                <div class="mac-row">
                  <label>连接池大小</label>
                  <div class="control">
                    <input type="number" v-model.number="config.servers[selectedServerIdx].pool_size" @blur="saveConfig" />
                  </div>
                </div>
                
                <div class="mac-row">
                  <label>超时时间 (秒)</label>
                  <div class="control">
                    <input type="number" v-model.number="config.servers[selectedServerIdx].timeout_seconds" @blur="saveConfig" />
                  </div>
                </div>
                
                <div class="mac-row">
                  <label>心跳间隔 (秒)</label>
                  <div class="control">
                    <input type="number" v-model.number="config.servers[selectedServerIdx].keep_alive_interval" @blur="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>校验主机密钥</label>
                  <div class="control">
                    <input type="checkbox" v-model="config.servers[selectedServerIdx].strict_host_key" @change="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>预置密钥指纹</label>
                  <div class="control">
                    <input v-model="config.servers[selectedServerIdx].host_key" placeholder="SHA256:xxxx（无人值守首次信任）" @blur="saveConfig" />
                  </div>
                </div>
                
              </div>
            </div>

          </div>
          <div v-else class="empty-hero">
            <div class="hero-icon">📡</div>
            <div class="hero-title">没有选中节点</div>
            <div class="hero-desc">在左侧列表选择或添加一个节点后，这里会显示它的连接与认证配置。</div>
            <button class="hero-cta" @click="addServer">＋ 添加节点</button>
          </div>
        </div>
      </div>

      <!-- Routing Tab -->
      <div v-show="currentTab === 'routing'" class="tab-pane">
        
        
        <div class="settings-group">
          <label>
            <input type="checkbox" v-model="config.routing.bypass_lan" @change="saveConfig" />
            开启大陆 IP 绕过 (直连) 与 局域网直连
          </label>
          <div style="font-size: 12px; color: var(--muted); margin-left: 24px; margin-top: 4px;">
            底层的二分查找引擎会毫秒级识别 8000+ 条国内 IP 规则，大幅降低国内访问延迟。
          </div>
          <div class="row" style="margin-top: 12px;">
            <label>路由规则订阅地址</label>
            <input v-model="config.general.chnroute_url" placeholder="例如: https://.../chnroutes.txt" @change="saveConfig" />
          </div>
          <div class="row" style="margin-top: 12px;">
            <label>订阅更新频率</label>
            <select v-model="config.general.chnroute_update_interval_hours" @change="saveConfig">
              <option :value="0.5">每 30 分钟</option>
              <option :value="1">每 1 小时</option>
              <option :value="2">每 2 小时</option>
              <option :value="6">每 6 小时</option>
              <option :value="12">每 12 小时</option>
              <option :value="24">每天一次 (24小时)</option>
              <option :value="0">禁用自动更新</option>
            </select>
          </div>
        </div>

        <h2 style="margin-top: 8px;">代理模式</h2>
        <select v-model="config.routing.mode" class="big-select" @change="saveConfig">
          <option value="global">🌍 全局代理 (Global) - 所有流量走 SSH 隧道 (除大陆直连外)</option>
          <option value="whitelist">🛡️ 白名单模式 (Whitelist) - 仅白名单内的域名走隧道</option>
          <option value="blacklist">🛑 黑名单模式 (Blacklist) - 黑名单内域名直连，其余走隧道</option>
          <option value="direct">⚡ 全局直连 (Direct) - 停用隧道，所有流量直连</option>
        </select>

        <div class="rule-lists">
          <div class="list-col">
            <h3>白名单 (每行一个)</h3>
            <textarea v-model="whitelistText" placeholder="支持 域名、IP 或 IP段，例如: google.com、192.168.1.100、10.0.0.0/8" @blur="saveConfig"></textarea>
          </div>
          <div class="list-col">
            <h3>黑名单 (每行一个)</h3>
            <textarea v-model="blacklistText" placeholder="支持 域名、IP 或 IP段，例如: baidu.com、192.168.0.0/16" @blur="saveConfig"></textarea>
          </div>
        </div>
      </div>

      <!-- 诊断页 -->
      <div v-show="currentTab === 'diagnostics'" class="tab-pane">
        <!-- 最近一次连接测试结果（持久展示） -->
        <div v-if="lastTestResult" class="settings-group" :style="{ borderLeft: '3px solid ' + (lastTestResult.ok ? 'var(--success)' : 'var(--danger)') }">
          <div style="font-size: 13px; color: var(--text);">
            {{ lastTestResult.ok ? "✓" : "✗" }} 节点「{{ lastTestResult.server }}」：{{ lastTestResult.text }}
          </div>
        </div>

        <!-- 运行指标 -->
        <div class="settings-group">
          <h3 class="group-title">运行指标</h3>
          <div v-if="diagMetrics" class="metric-grid">
            <div class="metric-card"><div class="metric-value">{{ diagMetrics.active_connections }}</div><div class="metric-label">活跃连接</div></div>
            <div class="metric-card"><div class="metric-value">{{ formatBytes(diagMetrics.bytes_tx) }}</div><div class="metric-label">上行流量</div></div>
            <div class="metric-card"><div class="metric-value">{{ formatBytes(diagMetrics.bytes_rx) }}</div><div class="metric-label">下行流量</div></div>
            <div class="metric-card"><div class="metric-value">{{ diagMetrics.ssh_pool_rebuilds }}</div><div class="metric-label">连接池重建</div></div>
            <div class="metric-card"><div class="metric-value">{{ diagMetrics.ssh_reconnects }}</div><div class="metric-label">单连接重连</div></div>
          </div>
          <div v-else class="empty-state" style="padding: 16px;">暂无指标</div>
        </div>

        <!-- 日志面板 -->
        <div class="settings-group" style="flex: 1; min-height: 200px;">
          <h3 class="group-title" style="display: flex; justify-content: space-between; align-items: center;">
            运行日志
            <button style="font-size: 12px; padding: 2px 10px;" @click="clearDiagLogs" :disabled="diagLogs.length === 0">清空</button>
          </h3>
          <div v-if="diagLogs.length === 0" class="empty-state" style="padding: 24px;">暂无日志</div>
          <div v-else class="log-panel">
            <div v-for="(entry, i) in diagLogs" :key="i" class="log-row">
              <span class="log-time">{{ entry.time }}</span>
              <span class="log-level" :class="entry.level.toLowerCase()">{{ entry.level }}</span>
              <span class="log-msg">{{ entry.message }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 主机密钥首次确认（TOFU）模态 -->
    <div v-if="pendingHostKey" class="hk-overlay" role="alertdialog" aria-modal="true" aria-label="首次安全验证">
      <div class="hk-modal">
        <div class="hk-eyebrow">首次安全验证</div>
        <h2 style="border-bottom:none; margin-bottom: 4px;">确认服务器主机密钥</h2>
        <p class="hk-desc">
          首次连接到该服务器。请核对以下 SHA256 指纹与服务器提供方公布的一致后再信任；
          信任后指纹将被保存，之后连接自动校验，若指纹发生变化会拒绝连接。
        </p>
        <div class="hk-detail">
          <div class="hk-row"><span>服务器</span><b>{{ pendingHostKey.host }}:{{ pendingHostKey.port }}</b></div>
          <div class="hk-row"><span>密钥类型</span><b>{{ pendingHostKey.key_type }}</b></div>
          <div class="hk-row"><span>SHA256 指纹</span><code class="hk-fp">{{ pendingHostKey.fingerprint }}</code></div>
        </div>
        <div class="hk-actions">
          <button class="hk-btn hk-reject" @click="resolveHostKey(false)">拒绝连接</button>
          <button class="hk-btn hk-trust" @click="resolveHostKey(true)">信任并连接</button>
        </div>
      </div>
    </div>

    <!-- 破坏性操作二次确认模态 -->
    <div v-if="confirmState" class="hk-overlay" role="alertdialog" aria-modal="true">
      <div class="hk-modal" style="width: 380px;">
        <p style="font-size: 13px; color: var(--text); margin: 0 0 16px;">{{ confirmState.text }}</p>
        <div class="hk-actions">
          <button class="hk-btn" @click="answerConfirm(false)">取消</button>
          <button class="hk-btn" style="color: var(--danger); border-color: var(--danger);" @click="answerConfirm(true)">确认删除</button>
        </div>
      </div>
    </div>

    <!-- Toast 轻提示（右下角） -->
    <div class="toast-wrap">
      <TransitionGroup name="toast">
        <div v-for="t in toasts" :key="t.id" class="toast" :class="t.type">{{ t.text }}</div>
      </TransitionGroup>
    </div>
  </div>
</template>

