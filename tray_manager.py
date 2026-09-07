import os
import sys
import pystray
from PIL import Image, ImageDraw
import threading
from typing import Callable, Optional

class TrayManager:
    def __init__(
        self,
        on_show_window: Callable,
        on_quick_fix: Callable,
        on_flush_dns: Callable,
        on_reset_dhcp: Callable,
        on_toggle_protection: Callable,
        on_exit: Callable
    ):
        self.on_show_window = on_show_window
        self.on_quick_fix = on_quick_fix
        self.on_flush_dns = on_flush_dns
        self.on_reset_dhcp = on_reset_dhcp
        self.on_toggle_protection = on_toggle_protection
        self.on_exit = on_exit

        self.icon: Optional[pystray.Icon] = None
        self.thread: Optional[threading.Thread] = None
        self.is_paused = False

    def create_tray_image(self, status: str = "ok") -> Image.Image:
        """
        Generates a modern high-DPI squircle tray icon with live status indicator badge.
        Status: 'ok' (Emerald), 'warning' (Amber), 'error' (Crimson), 'stopped' (Slate), 'offline' (Dark Red)
        """
        colors = {
            "ok": "#10b981",       # Emerald Green
            "warning": "#f59e0b",  # Amber Yellow
            "error": "#ef4444",    # Crimson Red
            "offline": "#b91c1c",  # Dark Crimson
            "stopped": "#64748b",  # Slate Gray
            "default": "#38bdf8"   # Cyber Sky Blue
        }
        accent = colors.get(status, colors["default"])

        base_img = None
        for filename in ["app_logo.png", "app_icon.ico"]:
            path = filename
            if hasattr(sys, "_MEIPASS"):
                path = os.path.join(sys._MEIPASS, filename)
            elif not os.path.exists(path):
                path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

            if os.path.exists(path):
                try:
                    base_img = Image.open(path).convert("RGBA")
                    break
                except Exception:
                    pass

        if base_img:
            work_img = base_img.resize((256, 256), Image.Resampling.LANCZOS)
            draw = ImageDraw.Draw(work_img)
            draw.ellipse((160, 160, 248, 248), fill="#0a0f1d", outline="#1e293b", width=8)
            draw.ellipse((172, 172, 236, 236), fill=accent)
            return work_img.resize((64, 64), Image.Resampling.LANCZOS)
        else:
            size = (64, 64)
            image = Image.new("RGBA", size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(image)
            draw.rounded_rectangle((4, 4, 60, 60), radius=14, fill="#0284c7")
            draw.rounded_rectangle((18, 18, 46, 46), radius=8, fill="#ffffff")
            draw.ellipse((40, 40, 60, 60), fill=accent, outline="#0a0f1d", width=2)
            return image

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem("🛡️ DNS Shield Pro (Open)", self._on_show, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("⚡ Quick Optimize (Fastest DNS)", self._on_quick_fix),
            pystray.MenuItem("🧹 Flush DNS Cache", self._on_flush),
            pystray.MenuItem("🔄 Reset to DHCP", self._on_reset_dhcp),
            pystray.MenuItem("⏸️ Pause / Resume Protection", self._on_toggle_pause),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Exit DNS Shield Pro", self._on_exit_clicked)
        )

    def start(self):
        """Starts the system tray icon in a dedicated daemon thread."""
        image = self.create_tray_image("ok")
        menu = self._build_menu()
        title = "DNS Shield Pro - Active Protection"

        self.icon = pystray.Icon("DNSShieldPro", image, title, menu)
        self.thread = threading.Thread(target=self.icon.run, daemon=True, name="TrayIconThread")
        self.thread.start()

    def update_status(self, status: str = "ok", tooltip: str = "DNS Shield Pro"):
        if self.icon:
            try:
                self.icon.icon = self.create_tray_image(status)
                self.icon.title = tooltip[:128]
            except Exception:
                pass

    def notify(self, title: str, message: str):
        if self.icon and hasattr(self.icon, "notify"):
            try:
                self.icon.notify(message, title)
            except Exception:
                pass

    def _on_show(self, icon, item):
        if self.on_show_window:
            self.on_show_window()

    def _on_quick_fix(self, icon, item):
        if self.on_quick_fix:
            self.on_quick_fix()

    def _on_flush(self, icon, item):
        if self.on_flush_dns:
            self.on_flush_dns()

    def _on_reset_dhcp(self, icon, item):
        if self.on_reset_dhcp:
            self.on_reset_dhcp()

    def _on_toggle_pause(self, icon, item):
        self.is_paused = not self.is_paused
        if self.on_toggle_protection:
            self.on_toggle_protection(not self.is_paused)

    def _on_exit_clicked(self, icon, item):
        self.stop()
        if self.on_exit:
            self.on_exit()

    def stop(self):
        if self.icon:
            try:
                self.icon.visible = False
                self.icon.stop()
            except Exception:
                pass
            self.icon = None
