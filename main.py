import sys
import os
import ctypes
import traceback
import customtkinter as ctk

# Enable UTF-8 console output for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Enable High-DPI awareness on Windows for crisp fonts and graphics
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
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
    Relaunches the current application with elevated Administrator privileges via Windows UAC.
    Handles both PyInstaller frozen single-binary EXEs and raw Python scripts correctly.
    """
    if is_admin():
        return True

    try:
        if getattr(sys, "frozen", False):
            # Compiled PyInstaller executable
            exe = sys.executable
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        else:
            # Raw python script
            script = os.path.abspath(sys.argv[0])
            params = f'"{script}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params.strip(), None, 1)

        if ret > 32:
            sys.exit(0)
    except Exception as e:
        print(f"[Main] Error requesting administrative elevation: {e}")

    return False

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler to ensure errors are recorded rather than crashing silently."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    import datetime
    err_text = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(f"[CRITICAL UNHANDLED EXCEPTION]\n{err_text}", file=sys.stderr)
    try:
        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crash_log.txt")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"\n--- Crash Log: {datetime.datetime.now()} ---\n{err_text}\n")
    except Exception:
        pass

sys.excepthook = handle_exception

def main():
    # Set explicit AppUserModelID so Windows Taskbar displays the dedicated app icon
    try:
        myappid = "DNSShieldPro.AutomatedDNS.v2"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

    # Ensure Administrator privileges for seamless network adapter configuration
    if not is_admin():
        try:
            if run_as_admin():
                sys.exit(0)
        except Exception:
            pass

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
        app.tray.notify(
            "DNS Shield Pro Started",
            "Active protection is running silently in the background."
        )

    root.mainloop()

if __name__ == "__main__":
    main()
