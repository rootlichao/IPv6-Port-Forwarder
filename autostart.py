# autostart.py
import sys
import platform
from pathlib import Path

def set_autostart(enable: bool, app_name: str = "IPv6PortTool"):
    """根据当前操作系统设置或取消开机自启"""
    system = platform.system()

    # 获取当前程序的可执行路径（兼容源码运行和 PyInstaller 打包后的 exe）
    exe = sys.executable
    script = "" if getattr(sys, "frozen", False) else f" {Path(sys.argv[0]).resolve()}"

    if system == "Linux":
        autostart_dir = Path.home() / ".config" / "autostart"
        desktop_file = autostart_dir / f"{app_name}.desktop"

        if enable:
            autostart_dir.mkdir(parents=True, exist_ok=True)
            # 加上 --startup 参数，让程序启动时静默隐藏
            content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                f"Name={app_name}\n"
                f"Exec={exe}{script} --startup\n" 
                "X-GNOME-Autostart-enabled=true\n"
            )
            desktop_file.write_text(content, encoding="utf-8")
        else:
            if desktop_file.exists():
                desktop_file.unlink()
        return True

    elif system == "Windows":
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            if enable:
                # 加上 --startup 参数，让程序启动时静默隐藏
                cmd = f'"{exe}"{script} --startup'
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, app_name)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"设置开机启动失败: {e}")
            return False

    elif system == "Darwin": # macOS
        plist_dir = Path.home() / "Library" / "LaunchAgents"
        plist = plist_dir / f"com.{app_name}.plist"
        
        if enable:
            plist_dir.mkdir(parents=True, exist_ok=True)
            script_path = Path(sys.argv[0]).resolve()
            content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.{app_name}</string>
    <key>ProgramArguments</key>
    <array><string>{exe}</string><string>{script_path}</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>"""
            plist.write_text(content, encoding="utf-8")
        else:
            if plist.exists():
                plist.unlink()
        return True

    return False