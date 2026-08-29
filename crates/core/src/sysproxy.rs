use std::process::Command;

pub fn set_system_proxy(enable: bool, host: &str, port: u16) -> anyhow::Result<()> {
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
            Command::new("networksetup").args(&["-setsocksfirewallproxy", &service, host, &port.to_string()]).output()?;
            Command::new("networksetup").args(&["-setsocksfirewallproxystate", &service, "on"]).output()?;
            // Ensure HTTP/HTTPS proxies are off to avoid conflicts
            Command::new("networksetup").args(&["-setwebproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setsecurewebproxystate", &service, "off"]).output()?;
        } else {
            Command::new("networksetup").args(&["-setsocksfirewallproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setwebproxystate", &service, "off"]).output()?;
            Command::new("networksetup").args(&["-setsecurewebproxystate", &service, "off"]).output()?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

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
        if enable {
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy", "mode", "'manual'"]).output().ok();
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy.socks", "host", &format!("'{}'", host)]).output().ok();
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy.socks", "port", &port.to_string()]).output().ok();
        } else {
            Command::new("gsettings").args(&["set", "org.gnome.system.proxy", "mode", "'none'"]).output().ok();
        }
    }

    // Suppress unused variables warnings if compiling for platforms not explicitly handled above
    let _ = enable;
    let _ = host;
    let _ = port;

    Ok(())
}
