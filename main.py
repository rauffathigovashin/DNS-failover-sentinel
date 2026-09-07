import sys
import os
import ctypes
import customtkinter as ctk

# Enable UTF-8 console output for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def is_admin() -> bool:
    """Checks whether the current process has Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin() -> bool:
    """
    Relaunches the current script with elevated Administrator privileges via Windows UAC.
    """
    if is_admin():
        return True

    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])

    try:
        # 1 = SW_SHOWNORMAL
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            None,
            1
        )
        if ret > 32:
            sys.exit(0)
    except Exception as e:
        print(f"[Main] Error requesting administrative elevation: {e}")

    return False

def main():
    # Set explicit AppUserModelID so Windows Taskbar uses and displays the dedicated icon
    try:
        myappid = "DNSShieldPro.AutomatedDNS.v2"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

    # If not running as admin, we can still start the app, but note the status
    # The UI will provide a prominent "Elevate as Admin" button if needed.
    from config_manager import ConfigManager
    from dns_monitor import DNSMonitor
    from app_gui import DNSGuardianApp

    config = ConfigManager()
    monitor = DNSMonitor(config)

    root = ctk.CTk()

    # Determine base directory (PyInstaller bundled vs raw script)
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Set Windows window and taskbar icon
    icon_path = os.path.join(base_dir, "app_icon.ico")
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except Exception:
            pass

    app = DNSGuardianApp(root, config, monitor, is_admin_func=is_admin, run_as_admin_func=run_as_admin)

    # Check for start minimized flag
    if "--minimized" in sys.argv or config.get("start_minimized", False):
        root.withdraw()
        app.tray.notify("DNS Shield Pro Started", "Active protection is running silently in the background.")

    root.mainloop()

if __name__ == "__main__":
    main()
