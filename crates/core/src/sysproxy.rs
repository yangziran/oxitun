use std::process::Command;
use std::sync::Mutex;

/// 系统代理管理模块
/// 跨平台（macOS / Windows / Linux）接管与还原系统 SOCKS5 代理，macOS 额外支持 DNS。
///
/// 关键语义：启用前**保存**原有代理/DNS 状态，禁用时**恢复**而非粗暴清空，
/// 避免覆盖用户已有配置、避免停止后残留指向本机的代理/DNS。
///
/// `set_dns`：macOS 下是否将系统 DNS 指向本地（仅当配置中存在 DNS 隧道时才应置 true，
/// 否则会把系统解析切到一个可能不存在的本地服务，导致断网）。
///
/// 幂等保证：`enable=false` 且本进程从未接管过（SAVED 为 None）时是安全 no-op，
/// 不做任何系统修改，避免误关用户原有代理/误清用户 DNS；重复禁用同理。
/// 恢复失败不会清空快照，下次 disable 可重试。
///
/// 已接管前的原始状态（进程内单例；GUI 单实例运行，够用）。
#[derive(Default)]
struct SavedState {
    /// 接管时探测到的网络服务名；恢复时优先用快照里的服务，
    /// 防止期间默认网卡切换导致恢复写到另一个网络（仅 macOS 有意义）
    #[cfg(target_os = "macos")]
    service: Option<String>,
    #[cfg(target_os = "macos")]
    socks_enabled: Option<String>,
    #[cfg(target_os = "macos")]
    socks_server: Option<String>,
    #[cfg(target_os = "macos")]
    socks_port: Option<String>,
    /// 原 DNS 服务器列表；None 表示原本无 DNS 设置（恢复时用 `empty` 还原为 DHCP 默认）。
    /// 仅当 dns_taken 为 true 时本字段才有意义（未接管 DNS 时不读、不恢复）
    #[cfg(target_os = "macos")]
    dns_servers: Option<Vec<String>>,
    /// 本进程是否实际接管了系统 DNS（仅当 enable && set_dns 时置 true）。
    /// disable 据此决定是否恢复 DNS：未接管时绝不能写 DNS，
    /// 否则会用陈旧快照覆盖用户在隧道运行期间合法修改的 DNS
    #[cfg(target_os = "macos")]
    dns_taken: bool,
    #[cfg(target_os = "windows")]
    proxy_enable: Option<u32>,
    #[cfg(target_os = "windows")]
    proxy_server: Option<String>,
    #[cfg(target_os = "windows")]
    proxy_override: Option<String>,
    #[cfg(target_os = "linux")]
    gnome_mode: Option<String>,
    #[cfg(target_os = "linux")]
    gnome_socks_host: Option<String>,
    #[cfg(target_os = "linux")]
    gnome_socks_port: Option<String>,
}

static SAVED: Mutex<Option<SavedState>> = Mutex::new(None);

/// 全局操作锁：整个 enable/disable 操作（含 disable 的「判断 → 取快照 → 恢复」）
/// 都在此锁下串行执行，避免并发调用出现「都通过 no-op 检查后 take(None) panic」的竞态。
static OP_LOCK: Mutex<()> = Mutex::new(());

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        anyhow::bail!("{} {:?} 退出码非零: {}", cmd, args, out.status);
    }
    Ok(out)
}

/// 恢复路径专用：单步失败不中断后续恢复，收集错误后尽力恢复，最后聚合返回。
fn finish_restore(errors: Vec<anyhow::Error>) -> anyhow::Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        let msg = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(anyhow::anyhow!("恢复系统代理部分步骤失败: {}", msg))
    }
}

/// 本进程是否正处于接管状态（即是否保存了接管前的原始状态）。
pub fn has_saved_state() -> bool {
    SAVED.lock().unwrap().is_some()
}

/// networksetup 对合法「未设置」状态的输出；与受检读取和恢复快照共用同一判定。
#[cfg(target_os = "macos")]
fn is_macos_legal_unset(output: &str) -> bool {
    let v = output.trim();
    v.is_empty() || v.contains("保留的先导字符") || v.starts_with("**")
}

/// networksetup -get 读取的可区分失败版本：Ok(None) 表示「读取成功但未设置」，
/// Err 表示命令失败——接管时必须失败即返回 Err，而不是按未设置继续。
#[cfg(target_os = "macos")]
fn ns_get_checked(args: &[&str]) -> anyhow::Result<Option<String>> {
    let out = Command::new("networksetup").args(args).output()?;
    if !out.status.success() {
        anyhow::bail!("networksetup {:?} 退出码非零: {}", args, out.status);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let v = s.trim();
    // 无设置时 networksetup 输出 "** ... 未设置" 之类提示，属合法未设置
    if is_macos_legal_unset(v) {
        return Ok(None);
    }
    Ok(Some(v.to_string()))
}

/// 选择恢复时使用的网络服务名：快照有记录则优先用快照（disable 期间默认网卡
/// 可能已切换，探测值会指向另一个网络），快照为空才退回本次探测值。
#[cfg(target_os = "macos")]
fn pick_restore_service(saved: Option<&str>, probed: &str) -> String {
    match saved {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => probed.to_string(),
    }
}

/// 解析 `networksetup -getsocksfirewallproxy` 输出中的开关行：
/// "Enabled: Yes" → Some("on")，"Enabled: No" → Some("off")，未找到 → None。
/// 注意输出末尾还有 "Authenticated Proxy Enabled: ..." 一行，必须按行首前缀匹配，
/// 不能直接取最后一行（那样拿到的通常是认证开关而非代理开关）。
#[cfg(target_os = "macos")]
fn parse_macos_proxy_enabled(output: &str) -> Option<&'static str> {
    for line in output.lines() {
        if let Some(v) = line.trim().strip_prefix("Enabled:") {
            return match v.trim() {
                "Yes" => Some("on"),
                "No" => Some("off"),
                _ => None,
            };
        }
    }
    None
}

/// 把 SOCKS 原始输出转换为接管前的开关恢复值。
/// 合法未设置必须明确恢复为 off；其他解析不出 Enabled 的输出仍视为读取失败。
#[cfg(target_os = "macos")]
fn macos_socks_restore_enabled(output: &str) -> Option<&'static str> {
    if is_macos_legal_unset(output) {
        Some("off")
    } else {
        parse_macos_proxy_enabled(output)
    }
}

/// SOCKS 开关恢复命令始终可执行；兼容修复前可能留下的空开关快照，按原本未设置恢复 off。
#[cfg(target_os = "macos")]
fn macos_socks_state_restore_args<'a>(service: &'a str, enabled: Option<&'a str>) -> Vec<&'a str> {
    vec![
        "-setsocksfirewallproxystate",
        service,
        enabled.unwrap_or("off"),
    ]
}

/// 解析 `networksetup -get...proxy` 输出中的 "Server:"/"Port:" 行（可能缺失或为空值）。
#[cfg(target_os = "macos")]
fn parse_macos_proxy_server_port(output: &str) -> (Option<String>, Option<String>) {
    let mut server = None;
    let mut port = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Server:") {
            let v = v.trim();
            if !v.is_empty() {
                server = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("Port:") {
            let v = v.trim();
            if !v.is_empty() {
                port = Some(v.to_string());
            }
        }
    }
    (server, port)
}

/// 去掉 `gsettings get` 输出首尾的引号：形如 "'manual'" → "manual"。
/// 纯函数便于跨平台单测；非 Linux 平台未调用，需允许 dead_code。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_gsettings_value(output: &str) -> String {
    output.trim().trim_matches('\'').to_string()
}

/// 解析 `networksetup -getdnsservers` 输出：每行一个 DNS 服务器，拆成独立条目。
/// 无设置（输出含 "There aren't any"）或为空时返回 None，恢复时应传 `empty`。
#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Option<Vec<String>> {
    if output.contains("There aren't any") {
        return None;
    }
    let servers: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

/// 组装 DNS 恢复命令参数：有快照服务器则逐个作为独立参数，
/// 原本无 DNS 设置（None）时传 `empty` 还原为 DHCP 默认。纯函数便于单测。
#[cfg(target_os = "macos")]
fn dns_restore_args<'a>(service: &'a str, servers: Option<&'a [String]>) -> Vec<&'a str> {
    let mut args: Vec<&str> = vec!["-setdnsservers", service];
    match servers {
        Some(list) => args.extend(list.iter().map(String::as_str)),
        None => args.push("empty"),
    }
    args
}

pub fn set_system_proxy(enable: bool, host: &str, port: u16) -> anyhow::Result<()> {
    set_system_proxy_ex(enable, host, port, false)
}

/// enable=true 接管代理；enable=false 还原到接管前状态。
/// set_dns 仅 macOS 生效：为 true 时才把系统 DNS 指向 127.0.0.1（需有本地 DNS 隧道）。
pub fn set_system_proxy_ex(
    enable: bool,
    host: &str,
    port: u16,
    set_dns: bool,
) -> anyhow::Result<()> {
    // 整个操作在全局锁下串行执行：disable 的「判断 → 取快照 → 恢复」在同一临界区内，
    // 避免两个并发 disable 都通过 no-op 检查后 take(None) panic
    let _op_guard = OP_LOCK.lock().unwrap();

    // 幂等保证：本进程从未接管过时，禁用必须是安全 no-op，不得触碰任何系统设置
    if !enable && SAVED.lock().unwrap().is_none() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg("networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | sed 's/.*) //'")
            .output()?;

        let mut service = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if service.is_empty() {
            service = "Wi-Fi".to_string();
        }

        if enable {
            // 保存现有状态（仅在首次接管时保存一次，避免二次接管覆盖原始值）
            let mut saved = SAVED.lock().unwrap();
            if saved.is_none() {
                // 只快照实际接管的 SOCKS；本程序从不接管 HTTP/HTTPS，不保存也不恢复。
                // 代理状态读取失败（命令非零/输出异常）必须报错返回，
                // 不能按「未设置」继续——否则恢复时会误清用户配置
                let socks_raw = ns_get_checked(&["-getsocksfirewallproxy", &service])?;
                // 合法未设置也保存明确的 off，disable 才能关闭本次写入的本地 SOCKS；
                // 非空异常输出解析失败仍拒绝接管，不会误当成未设置。
                let socks_enabled = Some(
                    macos_socks_restore_enabled(socks_raw.as_deref().unwrap_or(""))
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "解析 -getsocksfirewallproxy 输出失败（缺少 Enabled 行）"
                            )
                        })?
                        .to_string(),
                );
                let (socks_server, socks_port) = socks_raw
                    .as_deref()
                    .map(parse_macos_proxy_server_port)
                    .unwrap_or((None, None));
                *saved = Some(SavedState {
                    // 记录接管时的服务名，恢复时优先用快照值，防止默认网卡已切换
                    service: Some(service.clone()),
                    socks_enabled,
                    socks_server,
                    socks_port,
                    // DNS 快照延迟到确认要接管时再读（见下方 set_dns 分支）
                    dns_servers: None,
                    dns_taken: false,
                });
            }
            // 仅当本次确实要接管 DNS（set_dns）且此前未接管过时，才读取并记录 DNS 快照。
            // 读取必须用 ns_get_checked：瞬态失败若按「未设置」继续，
            // disable 时会把 None 当成"原本无 DNS"而清掉用户 DNS——失败即 bail 不接管
            if set_dns && !saved.as_ref().is_some_and(|s| s.dns_taken) {
                let s = saved.as_mut().expect("上方已保证快照存在");
                s.dns_servers = ns_get_checked(&["-getdnsservers", &service])?
                    .and_then(|v| parse_macos_dns_servers(&v));
                s.dns_taken = true;
            }
            drop(saved);

            run(
                "networksetup",
                &["-setsocksfirewallproxy", &service, host, &port.to_string()],
            )?;
            run(
                "networksetup",
                &["-setsocksfirewallproxystate", &service, "on"],
            )?;

            // 仅当确有本地 DNS 隧道时才接管 DNS，否则会把系统解析切到不存在的本地服务导致断网
            if set_dns {
                run("networksetup", &["-setdnsservers", &service, "127.0.0.1"])?;
            }
        } else {
            // 全程持有快照锁：仅当全部恢复步骤成功后才清空快照；
            // 任一步失败都保留快照，下次 disable 可重试（不再提前 take 丢失）
            let mut saved = SAVED.lock().unwrap();
            let s = saved.as_ref().expect("顶部已保证 SAVED 为 Some");
            // 优先恢复到快照记录的服务：disable 期间默认网卡可能已切换，
            // 本次探测值可能指向另一个网络；快照服务为空时才退回探测值
            let service = pick_restore_service(s.service.as_deref(), &service);
            let mut errors: Vec<anyhow::Error> = Vec::new();

            // 只要快照里有地址就恢复（不限于原开关为 on），先恢复地址再恢复开关，
            // 避免"开着的代理指向错误地址"的中间态
            if let (Some(server), Some(p)) = (&s.socks_server, &s.socks_port)
                && let Err(e) = run(
                    "networksetup",
                    &["-setsocksfirewallproxy", &service, server, p],
                )
            {
                errors.push(e);
            }
            // 还原接管前 SOCKS 开关。即使原本未设置也必须显式执行 off，
            // 否则本次开启的本地 SOCKS 会残留；旧空快照同样按 off 恢复。
            // 本程序从未接管 HTTP/HTTPS（Web/Secure Web），因此绝不恢复这两项，
            // 避免用陈旧快照覆盖用户运行期间的合法修改（与 dns_taken 语义一致）
            if let Err(e) = run(
                "networksetup",
                &macos_socks_state_restore_args(&service, s.socks_enabled.as_deref()),
            ) {
                errors.push(e);
            }
            // 还原 DNS：仅当本进程实际接管过 DNS 时才恢复；
            // 未接管（dns_taken=false）时必须跳过，保持用户当前 DNS 不动，
            // 避免用陈旧快照覆盖用户在隧道运行期间合法修改的 DNS
            if s.dns_taken
                && let Err(e) = run(
                    "networksetup",
                    &dns_restore_args(&service, s.dns_servers.as_deref()),
                )
            {
                errors.push(e);
            }
            let result = finish_restore(errors);
            if result.is_ok() {
                // 全部恢复成功才清空快照，失败保留以便重试
                *saved = None;
            }
            return result;
        }
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let sub_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        if enable {
            let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_READ | KEY_SET_VALUE)?;
            let mut saved = SAVED.lock().unwrap();
            if saved.is_none() {
                let pe: u32 = cur_var.get_value("ProxyEnable").unwrap_or(0);
                let ps: String = cur_var.get_value("ProxyServer").unwrap_or_default();
                let po: String = cur_var.get_value("ProxyOverride").unwrap_or_default();
                *saved = Some(SavedState {
                    proxy_enable: Some(pe),
                    proxy_server: Some(ps),
                    proxy_override: Some(po),
                });
            }
            drop(saved);

            let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_SET_VALUE)?;
            // IPv6 地址必须加方括号，否则冒号会与端口分隔符混淆
            let server = if host.contains(':') {
                format!("socks=[{}]:{}", host, port)
            } else {
                format!("socks={}:{}", host, port)
            };
            cur_var.set_value("ProxyEnable", &1u32)?;
            cur_var.set_value("ProxyServer", &server)?;
            cur_var.set_value("ProxyOverride", &"<local>")?;
        } else {
            // 全程持有快照锁：仅当全部恢复步骤成功后才清空快照，失败保留以便重试
            let mut saved = SAVED.lock().unwrap();
            let s = saved.as_ref().expect("顶部已保证 SAVED 为 Some");
            let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_SET_VALUE)?;
            let mut errors: Vec<anyhow::Error> = Vec::new();
            if let Err(e) = cur_var.set_value("ProxyEnable", &s.proxy_enable.unwrap_or(0)) {
                errors.push(e.into());
            }
            if let Err(e) =
                cur_var.set_value("ProxyServer", &s.proxy_server.clone().unwrap_or_default())
            {
                errors.push(e.into());
            }
            if let Err(e) = cur_var.set_value(
                "ProxyOverride",
                &s.proxy_override.clone().unwrap_or_default(),
            ) {
                errors.push(e.into());
            }
            let result = finish_restore(errors);
            if result.is_ok() {
                // 全部恢复成功才清空快照，失败保留以便重试
                *saved = None;
            }
            return result;
        }
    }

    #[cfg(target_os = "linux")]
    {
        /// gget 的可区分失败版本：Ok(None) 表示「读取成功但无值」，
        /// Err 表示 gsettings 命令失败——接管时必须失败即返回 Err，而不是按未设置继续。
        fn gget(schema: &str, key: &str) -> anyhow::Result<Option<String>> {
            let out = Command::new("gsettings")
                .args(["get", schema, key])
                .output()?;
            if !out.status.success() {
                anyhow::bail!(
                    "gsettings get {} {} 退出码非零: {}",
                    schema,
                    key,
                    out.status
                );
            }
            // gsettings 输出形如 "'manual'"，去掉引号；输出为空视为合法未设置
            let v = parse_gsettings_value(&String::from_utf8_lossy(&out.stdout));
            if v.is_empty() {
                return Ok(None);
            }
            Ok(Some(v))
        }

        if enable {
            let mut saved = SAVED.lock().unwrap();
            if saved.is_none() {
                // 任一读取失败都报错返回且快照保持 None，下次接管可重试
                *saved = Some(SavedState {
                    gnome_mode: gget("org.gnome.system.proxy", "mode")?,
                    gnome_socks_host: gget("org.gnome.system.proxy.socks", "host")?,
                    gnome_socks_port: gget("org.gnome.system.proxy.socks", "port")?,
                });
            }
            drop(saved);
            run(
                "gsettings",
                &["set", "org.gnome.system.proxy", "mode", "'manual'"],
            )?;
            run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.socks",
                    "host",
                    &format!("'{}'", host),
                ],
            )?;
            run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.socks",
                    "port",
                    &port.to_string(),
                ],
            )?;
        } else {
            // 全程持有快照锁：仅当全部恢复步骤成功后才清空快照，失败保留以便重试
            let mut saved = SAVED.lock().unwrap();
            let s = saved.as_ref().expect("顶部已保证 SAVED 为 Some");
            let mut errors: Vec<anyhow::Error> = Vec::new();
            // 还原到接管前的代理模式（而非一律 none），保留用户原有 auto/none 语义
            let mode = s.gnome_mode.clone().unwrap_or_else(|| "none".to_string());
            // 先恢复原 socks host/port，再恢复 mode：快照里有值就恢复（不限于 manual），
            // 避免 mode=manual 生效瞬间指向本程序已关闭的本地端口
            if let Some(h) = &s.gnome_socks_host
                && let Err(e) = run(
                    "gsettings",
                    &[
                        "set",
                        "org.gnome.system.proxy.socks",
                        "host",
                        &format!("'{}'", h),
                    ],
                )
            {
                errors.push(e);
            }
            if let Some(p) = &s.gnome_socks_port
                && let Err(e) = run(
                    "gsettings",
                    &["set", "org.gnome.system.proxy.socks", "port", p],
                )
            {
                errors.push(e);
            }
            if let Err(e) = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy",
                    "mode",
                    &format!("'{}'", mode),
                ],
            ) {
                errors.push(e);
            }
            let result = finish_restore(errors);
            if result.is_ok() {
                // 全部恢复成功才清空快照，失败保留以便重试
                *saved = None;
            }
            return result;
        }
    }

    let _ = enable;
    let _ = host;
    let _ = port;
    let _ = set_dns;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    // 不在单元测试中调用 set_system_proxy_ex：真实 networksetup 会修改宿主系统。
    // disable 不恢复 HTTP/HTTPS 由实现中不包含对应快照与命令保证；解析逻辑由以下纯函数测试覆盖。

    // 典型 `networksetup -getsocksfirewallproxy` 输出：开关在首行，最后一行是认证开关
    const SOCKS_ON: &str =
        "Enabled: Yes\nServer: 10.0.0.2\nPort: 1080\nAuthenticated Proxy Enabled: No\n";
    const SOCKS_OFF: &str = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: No\n";

    #[test]
    fn 解析开关_启用() {
        assert_eq!(parse_macos_proxy_enabled(SOCKS_ON), Some("on"));
    }

    #[test]
    fn 解析开关_关闭() {
        assert_eq!(parse_macos_proxy_enabled(SOCKS_OFF), Some("off"));
    }

    #[test]
    fn 解析开关_不能误取认证行() {
        // 最后一行是 "Authenticated Proxy Enabled: No"，
        // 旧实现取 lines().last() 会把它当成开关，必须区分
        let out = "Enabled: Yes\nServer: 1.2.3.4\nPort: 7890\nAuthenticated Proxy Enabled: No";
        assert_eq!(parse_macos_proxy_enabled(out), Some("on"));
    }

    #[test]
    fn 解析开关_缺失时返回_none() {
        assert_eq!(parse_macos_proxy_enabled(""), None);
        assert_eq!(
            parse_macos_proxy_enabled("Server: 1.2.3.4\nPort: 1080"),
            None
        );
        // 非空异常输出仍须拒绝接管，不能按合法未设置处理
        assert_eq!(
            macos_socks_restore_enabled("Server: 1.2.3.4\nPort: 1080"),
            None
        );
    }

    #[test]
    fn 开关恢复_空输出和原关闭都生成off命令() {
        for output in ["", SOCKS_OFF] {
            let enabled = macos_socks_restore_enabled(output);
            assert_eq!(enabled, Some("off"));
            assert_eq!(
                macos_socks_state_restore_args("Wi-Fi", enabled),
                vec!["-setsocksfirewallproxystate", "Wi-Fi", "off"]
            );
        }
    }

    #[test]
    fn 开关恢复_合法未设置提示和旧空快照也恢复off() {
        assert_eq!(
            macos_socks_restore_enabled("** SOCKS proxy is not set."),
            Some("off")
        );
        assert_eq!(
            macos_socks_state_restore_args("Wi-Fi", None),
            vec!["-setsocksfirewallproxystate", "Wi-Fi", "off"]
        );
    }

    #[test]
    fn 解析_server_port_正常() {
        let (server, port) = parse_macos_proxy_server_port(SOCKS_ON);
        assert_eq!(server.as_deref(), Some("10.0.0.2"));
        assert_eq!(port.as_deref(), Some("1080"));
    }

    #[test]
    fn 解析_server_port_空值视为缺失() {
        let (server, port) = parse_macos_proxy_server_port(SOCKS_OFF);
        assert_eq!(server, None);
        assert_eq!(port.as_deref(), Some("0"));
    }

    #[test]
    fn 解析_dns_多行拆分() {
        let out = "10.0.0.1\n8.8.8.8\n223.5.5.5\n";
        assert_eq!(
            parse_macos_dns_servers(out),
            Some(vec![
                "10.0.0.1".to_string(),
                "8.8.8.8".to_string(),
                "223.5.5.5".to_string()
            ])
        );
    }

    #[test]
    fn 解析_dns_单行() {
        assert_eq!(
            parse_macos_dns_servers("1.1.1.1"),
            Some(vec!["1.1.1.1".to_string()])
        );
    }

    #[test]
    fn 解析_dns_无设置返回_none() {
        assert_eq!(
            parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi."),
            None
        );
        assert_eq!(parse_macos_dns_servers(""), None);
        assert_eq!(parse_macos_dns_servers("  \n  \n"), None);
    }

    #[test]
    fn dns恢复参数_有快照逐个传入() {
        let servers = vec!["10.0.0.1".to_string(), "8.8.8.8".to_string()];
        assert_eq!(
            dns_restore_args("Wi-Fi", Some(&servers)),
            vec!["-setdnsservers", "Wi-Fi", "10.0.0.1", "8.8.8.8"]
        );
    }

    #[test]
    fn dns恢复参数_原本无设置用empty还原() {
        assert_eq!(
            dns_restore_args("Wi-Fi", None),
            vec!["-setdnsservers", "Wi-Fi", "empty"]
        );
        // 空列表同样按无设置处理
        assert_eq!(
            dns_restore_args("Wi-Fi", Some(&[])),
            vec!["-setdnsservers", "Wi-Fi"]
        );
    }

    #[test]
    fn 恢复服务名_优先用快照() {
        // disable 期间默认网卡可能已切换，探测值指向另一个网络，必须用快照服务
        assert_eq!(
            pick_restore_service(Some("Wi-Fi"), "USB 10/100/1000 LAN"),
            "Wi-Fi"
        );
        assert_eq!(pick_restore_service(Some("Wi-Fi"), "Wi-Fi"), "Wi-Fi");
    }

    #[test]
    fn 恢复服务名_快照为空才退回探测值() {
        assert_eq!(pick_restore_service(None, "Wi-Fi"), "Wi-Fi");
        assert_eq!(pick_restore_service(Some(""), "Wi-Fi"), "Wi-Fi");
    }
}

#[cfg(test)]
mod tests_common {
    use super::*;

    #[test]
    fn 解析_gsettings_去引号() {
        assert_eq!(parse_gsettings_value("'manual'\n"), "manual");
        assert_eq!(parse_gsettings_value("'none'"), "none");
    }

    #[test]
    fn 解析_gsettings_无引号原样返回() {
        assert_eq!(parse_gsettings_value("1080\n"), "1080");
        assert_eq!(parse_gsettings_value("  '127.0.0.1'  "), "127.0.0.1");
    }
}
