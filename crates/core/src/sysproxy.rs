use std::process::Command;

/// 系统代理管理模块
/// 支持跨平台（macOS, Windows, Linux）设置或取消系统的 SOCKS5 代理和 DNS 配置。
pub fn set_system_proxy(enable: bool, host: &str, port: u16) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // 自动探测当前生效的活跃网络接口名称（如 Wi-Fi 或 Ethernet）
        let output = Command::new("sh")
            .arg("-c")
            .arg("networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | sed 's/.*) //'")
            .output()?;
            
        let mut service = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if service.is_empty() {
            service = "Wi-Fi".to_string();
        }

        if enable {
            // 开启 SOCKS5 代理
            Command::new("networksetup").args(&["-setsocksfirewallproxy", &service, host, &port.to_string()]).output()?;
            Command::new("networksetup").args(&["-setsocksfirewallproxystate", &service, "on"]).output()?;
            
            // 将系统的 DNS 流量强制转发至本地监听的 DNS 隧道（端口通常为 53，受限于 OxiTun 架构这里一并劫持）
            Command::new("networksetup").args(&["-setdnsservers", &service, "127.0.0.1"]).output()?;

            // 确保 HTTP/HTTPS 代理处于关闭状态，防止冲突
            Command::new("networksetup").args(&["-setwebproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setsecurewebproxystate", &service, "off"]).output()?;
        } else {
            // 恢复网络默认状态
            Command::new("networksetup").args(&["-setsocksfirewallproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setdnsservers", &service, "empty"]).output()?;

            Command::new("networksetup").args(&["-setwebproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setsecurewebproxystate", &service, "off"]).output()?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        // 通过修改注册表 Internet Settings 影响全局 IE 代理设置
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let sub_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        let cur_var = hkcu.open_subkey_with_flags(sub_key, KEY_SET_VALUE)?;

        if enable {
            let server = format!("socks={}:{}", host, port);
            cur_var.set_value("ProxyEnable", &1u32)?;
            cur_var.set_value("ProxyServer", &server)?;
            cur_var.set_value("ProxyOverride", &"<local>")?;
        } else {
            cur_var.set_value("ProxyEnable", &0u32)?;
        }
    }

    #[cfg(target_os = "linux")]
    {
        // 针对 GNOME 桌面环境，使用 gsettings 修改系统代理模式
        if enable {
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy", "mode", "'manual'"]).output().ok();
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy.socks", "host", &format!("'{}'", host)]).output().ok();
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy.socks", "port", &port.to_string()]).output().ok();
        } else {
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy", "mode", "'none'"]).output().ok();
        }
    }

    // 防止在没有匹配到的平台上出现未使用变量的编译警告
    let _ = enable;
    let _ = host;
    let _ = port;

    Ok(())
}
