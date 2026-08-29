use tauri::menu::{Menu, SubmenuBuilder, PredefinedMenuItem};
use tauri::AppHandle;

#[cfg(target_os = "macos")]
pub fn create_app_menu(app_handle: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let app_menu = Menu::new(app_handle)?;
    
    // OxiTun
    let prefs = tauri::menu::MenuItemBuilder::with_id("preferences", "偏好设置...")
        .accelerator("CmdOrCtrl+,")
        .build(app_handle)?;
        
    let oxitun_menu = SubmenuBuilder::new(app_handle, "OxiTun")
        .item(&PredefinedMenuItem::about(app_handle, Some("关于 OxiTun"), None)?)
        .separator()
        .item(&prefs)
        .separator()
        .item(&PredefinedMenuItem::quit(app_handle, Some("退出 OxiTun"))?)
        .build()?;
        
    // Edit
    let edit_menu = SubmenuBuilder::new(app_handle, "编辑")
        .item(&PredefinedMenuItem::undo(app_handle, Some("撤销"))?)
        .item(&PredefinedMenuItem::redo(app_handle, Some("重做"))?)
        .separator()
        .item(&PredefinedMenuItem::cut(app_handle, Some("剪切"))?)
        .item(&PredefinedMenuItem::copy(app_handle, Some("复制"))?)
        .item(&PredefinedMenuItem::paste(app_handle, Some("粘贴"))?)
        .item(&PredefinedMenuItem::select_all(app_handle, Some("全选"))?)
        .build()?;

    let _ = app_menu.append(&oxitun_menu);
    let _ = app_menu.append(&edit_menu);
    
    Ok(app_menu)
}

#[cfg(not(target_os = "macos"))]
pub fn create_app_menu(app_handle: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    Menu::new(app_handle)
}
