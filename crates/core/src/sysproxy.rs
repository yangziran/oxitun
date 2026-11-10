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
/// 已接管前的原始状态（进程内单例；GUI 单实例运行，够用）。
#[derive(Default)]
struct SavedState {
    socks_enabled: Option<String>,
    dns_servers: Option<String>,
    web_enabled: Option<String>,
    secure_web_enabled: Option<String>,
    #[cfg(target_os = "windows")]
    proxy_enable: Option<u32>,
    #[cfg(target_os = "windows")]
    proxy_server: Option<String>,
    #[cfg(target_os = "windows")]
    proxy_override: Option<String>,
    #[cfg(target_os = "linux")]
    gnome_mode: Option<String>,
}

static SAVED: Mutex<Option<SavedState>> = Mutex::new(None);

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        anyhow::bail!("{} {:?} 退出码非零: {}", cmd, args, out.status);
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn ns_get(args: &[&str]) -> Option<String> {
    // -get... 在无设置时输出 "保留的先导字符..."
    let out = Command::new("networksetup").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let v = s.trim();
    if v.is_empty() || v.contains("保留的先导字符") || v.starts_with("**") {
        return None;
    }
    Some(v.to_string())
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
                let socks = ns_get(&["-getsocksfirewallproxy", &service])
                    .map(|s| s.lines().last().unwrap_or("off").trim().to_string());
                let web = ns_get(&["-getwebproxy", &service])
                    .map(|s| s.lines().last().unwrap_or("off").trim().to_string());
                let secure = ns_get(&["-getsecurewebproxy", &service])
                    .map(|s| s.lines().last().unwrap_or("off").trim().to_string());
                *saved = Some(SavedState {
                    socks_enabled: socks,
                    dns_servers: ns_get(&["-getdnsservers", &service]),
                    web_enabled: web,
                    secure_web_enabled: secure,
                    #[cfg(target_os = "windows")]
                    proxy_enable: None,
                    #[cfg(target_os = "windows")]
                    proxy_server: None,
                    #[cfg(target_os = "windows")]
                    proxy_override: None,
                    #[cfg(target_os = "linux")]
                    gnome_mode: None,
                });
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
            run(
                "networksetup",
                &["-setsocksfirewallproxystate", &service, "off"],
            )?;
            // 还原 DNS 与 HTTP(S) 代理到接管前状态
            let mut saved = SAVED.lock().unwrap();
            if let Some(s) = saved.take() {
                match s.dns_servers {
                    Some(servers) => {
                        run("networksetup", &["-setdnsservers", &service, &servers])?;
                    }
                    None => {
                        run("networksetup", &["-setdnsservers", &service, "empty"])?;
                    }
                }
                // 还原接管前 SOCKS 开关与 HTTP/HTTPS 代理状态
                if let Some(state) = s.socks_enabled {
                    run(
                        "networksetup",
                        &["-setsocksfirewallproxystate", &service, &state],
                    )?;
                }
                if let Some(state) = s.web_enabled {
                    run("networksetup", &["-setwebproxystate", &service, &state])?;
                }
                if let Some(state) = s.secure_web_enabled {
                    run(
                        "networksetup",
                        &["-setsecurewebproxystate", &service, &state],
                    )?;
                }
            }
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
                    ..Default::default()
                });
            }
            drop(saved);

            let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_SET_VALUE)?;
            let server = format!("socks={}:{}", host, port);
            cur_var.set_value("ProxyEnable", &1u32)?;
            cur_var.set_value("ProxyServer", &server)?;
            cur_var.set_value("ProxyOverride", &"<local>")?;
        } else {
            let mut saved = SAVED.lock().unwrap();
            let s = saved.take();
            drop(saved);
            let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_SET_VALUE)?;
            match s {
                Some(state) => {
                    cur_var.set_value("ProxyEnable", &state.proxy_enable.unwrap_or(0))?;
                    cur_var.set_value("ProxyServer", &state.proxy_server.unwrap_or_default())?;
                    cur_var
                        .set_value("ProxyOverride", &state.proxy_override.unwrap_or_default())?;
                }
                None => {
                    cur_var.set_value("ProxyEnable", &0u32)?;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        fn gget(key: &str) -> Option<String> {
            let out = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy", key])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            // gsettings 输出形如 "'manual'"，去掉引号
            Some(s.trim_matches('\'').to_string())
        }

        if enable {
            let mut saved = SAVED.lock().unwrap();
            if saved.is_none() {
                *saved = Some(SavedState {
                    gnome_mode: gget("mode"),
                    ..Default::default()
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
            let mut saved = SAVED.lock().unwrap();
            let mode = saved.take().and_then(|s| s.gnome_mode);
            drop(saved);
            // 还原到接管前的代理模式（而非一律 none），保留用户原有 auto/none 语义
            let restore = mode.unwrap_or_else(|| "none".to_string());
            run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy",
                    "mode",
                    &format!("'{}'", restore),
                ],
            )?;
        }
    }

    let _ = enable;
    let _ = host;
    let _ = port;
    Ok(())
}
