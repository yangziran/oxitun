#![allow(linker_messages)]
// 防止在 Windows Release 构建中出现额外的控制台窗口，请勿移除！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    desktop_lib::run()
}
