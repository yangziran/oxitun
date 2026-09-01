<script setup lang="ts">
import { ref, onMounted, computed } from "vue";
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
  reconnect_attempts: number;
  timeout_seconds: number;
  compression: boolean;
  check_host_ip: boolean;
  strict_host_key: boolean;
  address_family: string;
  host_key_algorithms?: string;
  kex_algorithms?: string;
  ciphers?: string;
}

interface TunnelConfig {
  name: string;
  server_names: string[];
  type: "local" | "dynamic" | "remote" | "dns" | "dns_dot" | "dns_doh";
  port: number;
  remote_addr?: string;
  share_on_lan: boolean;
}

interface Config {
  general: {
    auto_startup: boolean;
    auto_set_system_proxy: boolean;
    auto_connect?: boolean;
    pin_window?: boolean;
    chnroute_update_interval_hours?: number;
    chnroute_url: string;
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
const statusMsg = ref("");
const selectedServerIdx = ref(0);
const advancedExpanded = ref(false);



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
    
    getCurrentWindow().onFocusChanged(async ({ payload: focused }) => {
      if (focused) {
        try {
          await loadConfig();
          isRunning.value = await invoke("get_running_state");
        } catch(e) {}
      }
    });
  } catch (e: any) {
    statusMsg.value = `初始化错误: ${String(e)}`;
  }
});

async function loadConfig() {
  try {
    const res: any = await invoke("get_config");
    
    for (let srv of res.servers) {
      if (!srv.auth_type) srv.auth_type = "Password";
      if (!srv.address_family) srv.address_family = "Any";
      if (srv.pool_size === undefined) srv.pool_size = 8;
      if (srv.reconnect_attempts === undefined) srv.reconnect_attempts = 999;
      if (srv.timeout_seconds === undefined) srv.timeout_seconds = 15;
    }
    
    if (res.tunnels && res.tunnels.length > 0 && res.tunnels[0].server_names && res.tunnels[0].server_names.length === 0 && res.servers && res.servers.length > 0) {
      res.tunnels[0].server_names = [res.servers[0].name];
    }
    config.value = res;
  } catch (e) {
    statusMsg.value = "加载配置失败";
  }
}

async function saveConfig() {
  try {
    await invoke("save_config", { newConfig: config.value });
    statusMsg.value = "配置已保存";
    setTimeout(() => statusMsg.value = "", 3000);
  } catch (e) {
    statusMsg.value = `保存失败: ${e}`;
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

async function toggleProxy() {
  if (isStarting.value) return;
  startError.value = "";

  if (isRunning.value) {
    await invoke("stop_tunnels");
    isRunning.value = false;
  } else {
    try {
      if (config.value.servers.length === 0) {
        alert("错误: 请先在「节点管理」中添加至少一个服务器节点！");
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
      
      await invoke("start_tunnels");
      isRunning.value = true;
    } catch(e) {
      statusMsg.value = `错误: ${e}`;
      alert(`开启代理失败:\n${e}`);
    }
  }
}

function addTunnel() {
  config.value.tunnels.push({
    name: "新监听器",
    server_names: [config.value.servers.length > 0 ? config.value.servers[0].name : ""],
    type: "local",
    port: 8080,
    remote_addr: "127.0.0.1:80",
    share_on_lan: false
  });
  saveConfig();
}

function removeTunnel(index: number) {
  config.value.tunnels.splice(index, 1);
  saveConfig();
}

const isTesting = ref(false);

async function testConnection(serverName: string) {
  if (isTesting.value) return;
  isTesting.value = true;
  statusMsg.value = "正在测试连接...";
  try {
    await saveConfig();
    const result = await invoke("test_ssh_connection", { serverName });
    statusMsg.value = `✅ ${result}`;
  } catch (e: any) {
    statusMsg.value = `❌ 测试失败: ${String(e)}`;
  } finally {
    isTesting.value = false;
    setTimeout(() => { if (statusMsg.value.includes("测试")) statusMsg.value = ""; }, 5000);
  }
}

function addServer() {
  const newName = `节点 ${config.value.servers.length + 1}`;
  config.value.servers.push({
    name: newName, host: "127.0.0.1", port: 22, user: "root", pool_size: 8, keep_alive_interval: 3,
    reconnect_attempts: 999, timeout_seconds: 15, compression: false, check_host_ip: true,
    strict_host_key: true, address_family: "Any", auth_type: "Password"
  });
  selectedServerIdx.value = config.value.servers.length - 1; advancedExpanded.value = false;
}

function removeServer(index: number) { 
  if (index < 0 || index >= config.value.servers.length) return;
  config.value.servers.splice(index, 1); 
  if (selectedServerIdx.value >= config.value.servers.length) {
    selectedServerIdx.value = config.value.servers.length - 1; advancedExpanded.value = false;
  }
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
    </div>
    <div v-if="statusMsg" style="background: #fff3cd; color: #856404; padding: 4px 12px; font-size: 12px; text-align: center;">
      {{ statusMsg }}
    </div>
    <div class="content" :class="{ 'no-padding': currentTab === 'servers' }">
      <!-- General Tab -->
      <div v-show="currentTab === 'general'" class="tab-pane">
        
        <div class="settings-group mac-list-group">
          <h3 class="group-title">基础设置</h3>
          
          <div class="mac-row">
            <label>当前状态</label>
            <div class="control" style="justify-content: space-between; width: 100%;">
              <strong :style="{ color: isRunning ? '#28a745' : '#dc3545', fontSize: '13px' }">{{ isStarting ? "启动中..." : (isRunning ? "已开启 🟢" : "已关闭 🔴") }}</strong>
              <button :class="isRunning ? '' : 'primary-btn'" @click="toggleProxy" :disabled="isStarting" style="padding: 4px 12px; font-size: 12px;">
                {{ isStarting ? "..." : (isRunning ? "停止代理" : "开启主代理") }}
              </button> <div v-if="startError" style="color: #dc3545; font-size: 12px; margin-top: 8px; text-align: right;">
            {{ startError }}
          </div>
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
              <span style="font-size: 13px; color: #1d1d1f; white-space: nowrap;">{{ ['dns', 'dns_dot', 'dns_doh'].includes(config.tunnels[0].type) ? '上游 DNS:' : '目标地址:' }}</span>
              <input v-model="config.tunnels[0].remote_addr" placeholder="例如: 192.168.1.1:80" @blur="saveConfig" style="width: 200px; text-align: center;" />
            </div>
          </div>
          
          <div class="mac-row" style="padding-top: 8px; padding-bottom: 8px;">
            <div class="control" style="justify-content: center; gap: 8px; width: 100%; align-items: center;">
              <input type="checkbox" v-model="config.tunnels[0].share_on_lan" @change="saveConfig" style="margin: 0;" />
              <span style="font-size: 13px; color: #1d1d1f;">允许局域网连接</span>
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
              <div v-if="idx > 0" class="tunnel-card" style="background: #f9f9f9; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e5ea;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 12px; border-bottom: 1px solid #e5e5ea; padding-bottom: 8px;">
                  <div style="font-weight: 600; font-size: 13px; color: #1d1d1f;">扩展规则 {{ idx }}</div>
                  <button class="icon-btn" @click="removeTunnel(idx)" style="color: #dc3545; background: none; border: none; cursor: pointer; padding: 0; font-size: 12px;">删除规则</button>
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
                    <span style="font-size: 13px; color: #1d1d1f; white-space: nowrap;">{{ ['dns', 'dns_dot', 'dns_doh'].includes(tun.type) ? '上游 DNS:' : '目标地址:' }}</span>
                    <input v-model="tun.remote_addr" :placeholder="['dns_dot', 'dns_doh'].includes(tun.type) ? '例如: dot.pub 或 doh.pub:443' : (tun.type === 'dns' ? '例如: 8.8.8.8:53' : '例如: 192.168.1.1:80')" @blur="saveConfig" style="width: 200px; text-align: center;" />
                  </div>
                </div>
                
                <div class="mac-row" style="padding-top: 8px; padding-bottom: 4px;">
                  <div class="control" style="justify-content: center; gap: 8px; width: 100%; align-items: center;">
                    <input type="checkbox" v-model="tun.share_on_lan" @change="saveConfig" style="margin: 0;" />
                    <span style="font-size: 13px; color: #1d1d1f;">允许局域网连接</span>
                  </div>
                </div>
              </div>
            </template>
            <div v-if="config.tunnels.length <= 1" style="text-align: center; color: #86868b; font-size: 12px; padding: 12px 0;">
              暂无自定义规则
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
          </div>
          <div class="servers-toolbar">
            <button class="icon-btn" @click="addServer" title="添加节点">＋</button>
            <button class="icon-btn" @click="removeServer(selectedServerIdx)" :disabled="selectedServerIdx < 0 || selectedServerIdx >= config.servers.length" title="删除节点">－</button>
            <div class="spacer"></div>
            <span style="font-size: 11px; color: #86868b; margin-right: 8px;">共 {{ config.servers.length }} 个节点</span>
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
                    <option value="Password">密码</option>
                    <option value="PrivateKey">私钥</option>
                  </select>
                  
                  <input v-if="config.servers[selectedServerIdx].auth_type === 'Password'" 
                         type="password" v-model="config.servers[selectedServerIdx].password" 
                         placeholder="输入登录密码" @blur="saveConfig" style="flex: 1;" />
                         
                  <input v-else 
                         v-model="config.servers[selectedServerIdx].key_path" 
                         placeholder="例如: ~/.ssh/id_rsa" @blur="saveConfig" style="flex: 1;" />
                </div>
              </div>

              <div style="margin: 12px 0;">
                <button class="primary-btn" @click="testConnection(config.servers[selectedServerIdx].name)" :disabled="isTesting" style="background: #28a745; width: 100%;">
                  {{ isTesting ? "测试中..." : "保存并测试" }}
                </button>
              </div>
            </div>

            <div class="settings-group mac-list-group">
              <div style="display: flex; justify-content: space-between; align-items: center; cursor: pointer; padding: 4px 0;" @click="advancedExpanded = !advancedExpanded">
                <h3 class="group-title" style="margin: 0; border: none; padding: 0;">高级配置</h3>
                <span style="color: #86868b; font-size: 12px; font-weight: 500; background: #f0f0f0; padding: 4px 8px; border-radius: 4px;">{{ advancedExpanded ? '▲ 收起' : '▼ 展开' }}</span>
              </div>
              
              <div v-show="advancedExpanded" style="margin-top: 12px; border-top: 1px solid #f0f0f0; padding-top: 8px;">
                
                <div class="mac-row">
                  <label>连接池大小</label>
                  <div class="control">
                    <input type="number" v-model.number="config.servers[selectedServerIdx].pool_size" @blur="saveConfig" />
                  </div>
                </div>
                
                <div class="mac-row">
                  <label>重试次数 (次)</label>
                  <div class="control">
                    <input type="number" v-model.number="config.servers[selectedServerIdx].reconnect_attempts" @blur="saveConfig" />
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
                  <label>数据压缩</label>
                  <div class="control">
                    <input type="checkbox" v-model="config.servers[selectedServerIdx].compression" @change="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>严格校验主机 IP</label>
                  <div class="control">
                    <input type="checkbox" v-model="config.servers[selectedServerIdx].check_host_ip" @change="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>拒绝密钥变更</label>
                  <div class="control">
                    <input type="checkbox" v-model="config.servers[selectedServerIdx].strict_host_key" @change="saveConfig" />
                  </div>
                </div>
                
                <div class="mac-row">
                  <label>网络协议</label>
                  <div class="control" style="gap: 12px;">
                    <label style="font-size: 13px; font-weight: normal; margin:0;"><input type="radio" value="V4" v-model="config.servers[selectedServerIdx].address_family" @change="saveConfig"> IPv4</label>
                    <label style="font-size: 13px; font-weight: normal; margin:0;"><input type="radio" value="V6" v-model="config.servers[selectedServerIdx].address_family" @change="saveConfig"> IPv6</label>
                    <label style="font-size: 13px; font-weight: normal; margin:0;"><input type="radio" value="Any" v-model="config.servers[selectedServerIdx].address_family" @change="saveConfig"> 不限</label>
                  </div>
                </div>

                <div class="mac-row">
                  <label>主机密钥算法</label>
                  <div class="control">
                    <input v-model="config.servers[selectedServerIdx].host_key_algorithms" placeholder="默认算法" @blur="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>密钥交换算法</label>
                  <div class="control">
                    <input v-model="config.servers[selectedServerIdx].kex_algorithms" placeholder="默认算法" @blur="saveConfig" />
                  </div>
                </div>

                <div class="mac-row">
                  <label>加密算法</label>
                  <div class="control">
                    <input v-model="config.servers[selectedServerIdx].ciphers" placeholder="默认算法" @blur="saveConfig" />
                  </div>
                </div>

              </div>
            </div>

          </div>
          <div v-else class="empty-state">
            没有选中节点，请在左侧添加。
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
          <div style="font-size: 12px; color: #86868b; margin-left: 24px; margin-top: 4px;">
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
    </div>
  </div>
</template>

<style>
/* CSS Resets & Base Styles */
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", Arial, sans-serif; background: #ececeb;  color: #1d1d1f; overflow: hidden; }
.mac-window { display: flex; flex-direction: column; height: 100vh; }
.toolbar { display: flex; background: #f5f5f5; border-bottom: 1px solid #d2d2d7; padding: 8px 16px; gap: 8px; justify-content: center; box-shadow: 0 1px 2px rgba(0,0,0,0.02); }
.tab { padding: 4px 14px; cursor: pointer; border-radius: 6px; color: #515154; font-size: 13px; font-weight: 500; transition: all 0.2s; }
.tab:hover { background: #e5e5e5; }
.tab.active { background: #007aff; color: white; }
.content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.tab-pane { padding: 24px; overflow-y: auto; flex: 1; }

h2 { font-size: 15px; font-weight: 600; color: #1d1d1f; margin-top: 0; margin-bottom: 12px; padding-bottom: 4px; border-bottom: 1px solid #e5e5ea; }
h3 { font-size: 13px; color: #86868b; margin-bottom: 8px; }
.group-title { font-size: 13px; color: #86868b; font-weight: 500; margin: 0 0 12px 0; border-bottom: 1px solid #f0f0f0; padding-bottom: 8px;}

.status-panel { display: flex; align-items: center; justify-content: space-between; background: #ffffff; padding: 16px 20px; border-radius: 8px; border: 1px solid #e5e5ea; margin-bottom: 12px; }
.status-panel p { margin: 0; font-size: 14px; }
.settings-group { display: flex; flex-direction: column; background: white; padding: 16px; border-radius: 8px; border: 1px solid #e5e5ea; margin-bottom: 12px; }
.settings-group label { font-size: 13px; display: flex; align-items: center; gap: 8px; cursor: pointer; }

input, select, textarea { -webkit-user-select: text; user-select: text; padding: 6px 10px; border: 1px solid #c8c8cc; border-radius: 6px; font-size: 13px; outline: none; background: #ffffff; }
input:focus, select:focus, textarea:focus { border-color: #007aff; box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.2); }
.short-input { width: 120px; }
.lan-share { font-size: 12px; display: flex; align-items: center; gap: 8px; }
textarea { height: 150px; resize: none; font-family: monospace; }

.tunnel-list { display: flex; flex-direction: column; gap: 12px; }
.tunnel-card { background: white; border: 1px solid #e5e5ea; border-radius: 8px; padding: 12px 16px; display: flex; flex-direction: column; }
.tunnel-row { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.tunnel-row label { color: #515154; margin-right: 4px; }
.add-btn { background: #fff; border: 1px dashed #c8c8cc; color: #007aff; padding: 8px; border-radius: 8px; cursor: pointer; font-size: 13px; }
.add-btn:hover { background: #f0f8ff; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px 24px; }
.row { display: flex; flex-direction: column; gap: 6px; }
.row label { font-size: 12px; color: #86868b; font-weight: 500;}

.rule-lists { display: flex; gap: 24px; margin-top: 8px; }
.list-col { flex: 1; display: flex; flex-direction: column; }
.big-select { width: 100%; padding: 10px; font-size: 14px; }

button { padding: 6px 14px; border: 1px solid #d2d2d7; background: #ffffff; border-radius: 6px; cursor: pointer; font-size: 13px; color: #1d1d1f; box-shadow: 0 1px 1px rgba(0,0,0,0.04); }
button:active { background: #f0f0f0; }
.primary-btn { background: #007aff; color: white; border: none; font-weight: 500; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }
.primary-btn:active { background: #0066d6; }

/* Master-Detail Layout */
.master-detail { display: flex; height: 100%; background: #ececeb; }
.master-list { width: 240px; border-right: 1px solid #d2d2d7; display: flex; flex-direction: column; background: #fcfcfc; }
.servers-scroll { flex: 1; overflow-y: auto; padding: 12px; }
.server-row { padding: 8px 12px; border-radius: 6px; cursor: pointer; margin-bottom: 4px; border: 1px solid transparent; transition: all 0.1s; }
.server-row:hover { background: #f0f0f0; }
.server-active { background: #007aff !important; color: white; border-color: #0066d6; }
.server-active .srv-sub { color: #cce4ff; }
.srv-title { font-weight: 600; font-size: 13px; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
.srv-sub { font-size: 11px; color: #86868b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
.servers-toolbar { display: flex; border-top: 1px solid #e5e5ea; padding: 8px 12px; align-items: center; background: #f9f9f9; }
.icon-btn { padding: 2px 8px; font-size: 14px; font-family: monospace; border-radius: 4px; margin-right: -1px; }
.spacer { flex: 1; }

.detail-view { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.detail-scroll { flex: 1; overflow-y: auto; padding: 24px 32px; }
.empty-state { flex: 1; display: flex; align-items: center; justify-content: center; color: #86868b; font-size: 14px; }

.mac-list-group { padding: 12px 20px; }
.mac-list-group .group-title { font-size: 14px; color: #1d1d1f; font-weight: 600; margin: 0 0 8px 0; border: none; }
.mac-row { display: flex; flex-direction: row; align-items: center; justify-content: flex-start; padding: 10px 0; border-bottom: 1px solid #f0f0f0; }
.mac-row:last-child { border-bottom: none; }
.mac-row > label { font-size: 13px; color: #1d1d1f; font-weight: 500; flex-shrink: 0; width: 140px; text-align: right; padding-right: 16px; margin: 0; display: block; }
.mac-row .control { flex: 1; display: flex; justify-content: flex-start; align-items: center; }
.mac-row input:not([type="checkbox"]):not([type="radio"]), .mac-row select { width: 100%; max-width: 280px; text-align: left; }


.server-row.dragging { opacity: 0.4; transform: scale(0.98); }
.server-row.drag-over { border-top: 2px solid #007aff; border-radius: 2px; }


.server-row > * { pointer-events: none; }

</style>
