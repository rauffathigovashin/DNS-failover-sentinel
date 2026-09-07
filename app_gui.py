import os
import sys
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import threading
import time
import re
from typing import Optional, Dict, List, Callable
from PIL import Image

from dns_core import DNSCore
from dns_monitor import DNSMonitor
from config_manager import ConfigManager
from tray_manager import TrayManager

# Appearance & Color Theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class LatencyGraphCanvas(ctk.CTkFrame):
    """
    High-performance, anti-aliased live latency sparkline visualizer.
    Renders live DNS ping history with color-coded latency zones.
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="#0b1120", corner_radius=10, border_width=1, border_color="#1e293b", **kwargs)
        self.canvas = tk.Canvas(
            self,
            bg="#060a14",
            highlightthickness=0,
            bd=0,
            height=110
        )
        self.canvas.pack(fill="both", expand=True, padx=8, pady=8)
        self.history_data: List[Dict] = []
        self.canvas.bind("<Configure>", lambda e: self.redraw())

    def update_data(self, history: List[Dict]):
        self.history_data = history
        self.redraw()

    def redraw(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 50 or h < 30:
            return

        pad_l = 42
        pad_r = 16
        pad_t = 16
        pad_b = 22
        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b

        # Grid lines (25ms, 50ms, 100ms)
        max_scale_ms = 120.0
        grid_vals = [25.0, 50.0, 100.0]

        for val in grid_vals:
            y = pad_t + plot_h - (val / max_scale_ms) * plot_h
            self.canvas.create_line(pad_l, y, w - pad_r, y, fill="#131d33", dash=(3, 3))
            self.canvas.create_text(
                pad_l - 6, y,
                text=f"{int(val)}ms",
                anchor="e",
                fill="#475569",
                font=("Segoe UI", 8)
            )

        # Baseline (0ms)
        self.canvas.create_line(pad_l, pad_t + plot_h, w - pad_r, pad_t + plot_h, fill="#1e293b")

        if not self.history_data:
            self.canvas.create_text(
                w / 2, h / 2,
                text="Awaiting live ping telemetry...",
                fill="#475569",
                font=("Segoe UI", 10, "italic")
            )
            return

        # Calculate statistics
        valid_ms = [p["latency"] for p in self.history_data if p["latency"] < 9000]
        cur_ms = self.history_data[-1]["latency"] if self.history_data else 0.0
        cur_status = self.history_data[-1].get("status", "ok") if self.history_data else "ok"
        avg_ms = round(sum(valid_ms) / len(valid_ms), 1) if valid_ms else 0.0
        min_ms = min(valid_ms) if valid_ms else 0.0

        # Plot data points
        n = 30
        step_x = plot_w / (n - 1) if n > 1 else plot_w
        data_points = self.history_data[-n:]
        offset_start = n - len(data_points)

        coords = []
        for i, item in enumerate(data_points):
            idx = offset_start + i
            x = pad_l + idx * step_x
            ms = item["latency"]
            clamped_ms = min(ms, max_scale_ms)
            y = pad_t + plot_h - (clamped_ms / max_scale_ms) * plot_h
            coords.append((x, y, ms, item.get("status", "ok")))

        # Draw connecting line segments with color-coded gradients
        for i in range(len(coords) - 1):
            x1, y1, ms1, st1 = coords[i]
            x2, y2, ms2, st2 = coords[i + 1]

            if st2 == "offline" or st2 == "error" or ms2 >= 9000:
                line_color = "#ef4444"
            elif ms2 < 40:
                line_color = "#10b981"
            elif ms2 < 100:
                line_color = "#f59e0b"
            else:
                line_color = "#ef4444"

            self.canvas.create_line(x1, y1, x2, y2, fill=line_color, width=2, smooth=True)

        # Draw glowing point nodes
        for x, y, ms, st in coords:
            if st in ("offline", "error") or ms >= 9000:
                node_color = "#ef4444"
                radius = 3
            elif ms < 40:
                node_color = "#34d399"
                radius = 2.5
            elif ms < 100:
                node_color = "#fbbf24"
                radius = 2.5
            else:
                node_color = "#f87171"
                radius = 3

            self.canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill=node_color, outline="#060a14", width=1
            )

        # Header live telemetry HUD overlay
        if cur_status == "offline":
            cur_color = "#ef4444"
            cur_text = "OFFLINE (No Network Link)"
        elif cur_ms >= 9000:
            cur_color = "#f59e0b"
            cur_text = "TIMEOUT"
        else:
            cur_color = "#10b981" if cur_ms < 40 else ("#f59e0b" if cur_ms < 100 else "#ef4444")
            cur_text = f"{cur_ms} ms"

        stat_summary = f"Current: {cur_text}  •  Fastest: {min_ms} ms  •  Average: {avg_ms} ms"
        self.canvas.create_text(
            pad_l, pad_t - 4,
            text=stat_summary,
            anchor="w",
            fill="#94a3b8",
            font=("Segoe UI", 9, "bold")
        )


class DNSGuardianApp:
    def __init__(
        self,
        root: ctk.CTk,
        config_manager: ConfigManager,
        monitor: DNSMonitor,
        is_admin_func: Optional[Callable[[], bool]] = None,
        run_as_admin_func: Optional[Callable[[], bool]] = None
    ):
        self.root = root
        self.config = config_manager
        self.monitor = monitor
        self.is_admin = is_admin_func() if is_admin_func else False
        self.run_as_admin_func = run_as_admin_func

        # App Configuration
        self.root.title("DNS Shield Pro v2.5 - Automated DNS Sentinel & Latency Optimizer")
        self.root.geometry("1080x810")
        self.root.minsize(980, 700)

        # Internal State
        self.adapters_list: List[Dict] = []
        self.benchmarks_data: List[Dict] = []
        self.active_category = "All"
        self.search_filter_text = ""
        self.log_filter_level = "all"
        self.raw_logs: List[Dict] = []
        self.toast_after_id = None

        # System Tray Integration
        self.tray = TrayManager(
            on_show_window=self.show_window_from_tray,
            on_quick_fix=self.quick_optimize_async,
            on_flush_dns=self.flush_dns_action,
            on_reset_dhcp=self.reset_dhcp_action,
            on_toggle_protection=self.tray_toggle_protection,
            on_exit=self.full_exit
        )
        self.tray.start()

        # Window Close Event Handling
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Monitor Callbacks
        self.monitor.on_status_change = self._on_monitor_status
        self.monitor.on_log_message = self._on_monitor_log
        self.monitor.on_dns_switched = self._on_dns_switched

        # Build Interface
        self._build_ui()

        # Initial Data Population
        self.refresh_adapters()
        self.monitor.start()

    def _safe_call(self, fn, *args):
        """Thread-safe Tkinter invocation."""
        try:
            self.root.after(0, fn, *args)
        except Exception:
            pass

    def show_toast(self, message: str, color: str = "#064e3b", text_color: str = "#34d399"):
        """Displays an elegant, auto-dismissing action toast notification."""
        self.toast_lbl.configure(text=message, fg_color=color, text_color=text_color)
        self.toast_frame.pack(fill="x", padx=16, pady=(0, 6))

        if self.toast_after_id:
            self.root.after_cancel(self.toast_after_id)
        self.toast_after_id = self.root.after(3500, lambda: self.toast_frame.pack_forget())

    # ==================== UI CONSTRUCTION ====================
    def _build_ui(self):
        self.main_container = ctk.CTkFrame(self.root, fg_color="#080d1a", corner_radius=0)
        self.main_container.pack(fill="both", expand=True)

        # 1. Header Bar
        self._build_header(self.main_container)

        # Toast notification banner (hidden by default)
        self.toast_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.toast_lbl = ctk.CTkLabel(
            self.toast_frame,
            text="",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            corner_radius=8,
            padx=14,
            pady=4
        )
        self.toast_lbl.pack(fill="x")

        # 2. Top Metric Cards (4 Deck)
        self._build_status_deck(self.main_container)

        # 3. Main Tabs
        self._build_tabs(self.main_container)

    def _build_header(self, parent):
        header_frame = ctk.CTkFrame(
            parent,
            fg_color="#0f172a",
            height=76,
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        header_frame.pack(fill="x", padx=16, pady=(12, 6))
        header_frame.pack_propagate(False)

        # Left: Brand Logo and Title
        left_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        left_box.pack(side="left", padx=16, pady=8)

        brand_row = ctk.CTkFrame(left_box, fg_color="transparent")
        brand_row.pack(anchor="w")

        # Logo Image
        self.brand_logo_image = None
        for filename in ["app_logo.png", "app_icon.ico"]:
            p = filename
            if hasattr(sys, "_MEIPASS"):
                p = os.path.join(sys._MEIPASS, filename)
            elif not os.path.exists(p):
                p = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
            if os.path.exists(p):
                try:
                    pil_logo = Image.open(p)
                    self.brand_logo_image = ctk.CTkImage(light_image=pil_logo, dark_image=pil_logo, size=(32, 32))
                    break
                except Exception:
                    pass

        if self.brand_logo_image:
            logo_lbl = ctk.CTkLabel(brand_row, image=self.brand_logo_image, text="")
            logo_lbl.pack(side="left", padx=(0, 10))

        self.title_lbl = ctk.CTkLabel(
            brand_row,
            text="DNS SHIELD PRO",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="#38bdf8"
        )
        self.title_lbl.pack(side="left")

        ver_badge = ctk.CTkLabel(
            brand_row,
            text="v2.5",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            fg_color="#0284c7",
            text_color="#ffffff",
            corner_radius=6,
            padx=6,
            pady=1
        )
        ver_badge.pack(side="left", padx=(8, 0))

        self.subtitle_lbl = ctk.CTkLabel(
            left_box,
            text="Automated DNS Failover Sentinel • Multi-Provider Latency Benchmarking • Zero-Downtime Protection",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#94a3b8"
        )
        self.subtitle_lbl.pack(anchor="w")

        # Right Controls: Admin Badge, Status Badge & Protection Toggle
        right_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        right_box.pack(side="right", padx=16, pady=8)

        # Admin Badge / Elevation Button
        if self.is_admin:
            self.admin_badge = ctk.CTkLabel(
                right_box,
                text="🛡️ ADMIN",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                fg_color="#064e3b",
                text_color="#34d399",
                corner_radius=6,
                padx=10,
                pady=4
            )
            self.admin_badge.pack(side="right", padx=(8, 0))
        else:
            self.admin_badge = ctk.CTkButton(
                right_box,
                text="⚠️ ELEVATE TO ADMIN",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                fg_color="#78350f",
                hover_color="#92400e",
                text_color="#fde68a",
                corner_radius=6,
                height=26,
                command=self.request_elevation
            )
            self.admin_badge.pack(side="right", padx=(8, 0))

        # Protection State Badge
        self.status_badge = ctk.CTkLabel(
            right_box,
            text="● PROTECTED",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#064e3b",
            text_color="#34d399",
            corner_radius=6,
            padx=12,
            pady=4
        )
        self.status_badge.pack(side="right", padx=(8, 0))

        # Master Protection Switch
        self.protection_switch = ctk.CTkSwitch(
            right_box,
            text="Active Protection",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            command=self.toggle_protection,
            progress_color="#0284c7"
        )
        self.protection_switch.select()
        self.protection_switch.pack(side="right")

    def _build_status_deck(self, parent):
        deck_frame = ctk.CTkFrame(parent, fg_color="transparent")
        deck_frame.pack(fill="x", padx=16, pady=4)
        deck_frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="metric_card")

        # Card 1: Network Adapter
        c1 = ctk.CTkFrame(deck_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        c1.grid(row=0, column=0, padx=(0, 6), sticky="nsew", pady=4)
        self.c1_title = ctk.CTkLabel(c1, text="🌐 NETWORK ADAPTER", font=ctk.CTkFont(size=11, weight="bold"), text_color="#64748b")
        self.c1_title.pack(anchor="w", padx=14, pady=(10, 2))

        adapt_row = ctk.CTkFrame(c1, fg_color="transparent")
        adapt_row.pack(fill="x", padx=14, pady=(2, 4))

        self.adapter_dropdown = ctk.CTkOptionMenu(
            adapt_row,
            values=["Auto-Detect (Primary)"],
            command=self.on_adapter_selected,
            fg_color="#1e293b",
            button_color="#334155",
            text_color="#f8fafc",
            height=28
        )
        self.adapter_dropdown.pack(side="left", fill="x", expand=True)

        self.btn_refresh_adapters = ctk.CTkButton(
            adapt_row,
            text="🔄",
            width=28,
            height=28,
            fg_color="#1e293b",
            hover_color="#334155",
            command=self.refresh_adapters
        )
        self.btn_refresh_adapters.pack(side="left", padx=(4, 0))

        self.adapter_sub_lbl = ctk.CTkLabel(c1, text="Status: Connected", font=ctk.CTkFont(size=11), text_color="#10b981")
        self.adapter_sub_lbl.pack(anchor="w", padx=14, pady=(0, 8))

        # Card 2: Active DNS Resolver
        c2 = ctk.CTkFrame(deck_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        c2.grid(row=0, column=1, padx=6, sticky="nsew", pady=4)
        self.c2_title = ctk.CTkLabel(c2, text="🎯 ACTIVE DNS RESOLVER", font=ctk.CTkFont(size=11, weight="bold"), text_color="#64748b")
        self.c2_title.pack(anchor="w", padx=14, pady=(10, 2))
        self.current_dns_lbl = ctk.CTkLabel(
            c2,
            text="Detecting...",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color="#38bdf8"
        )
        self.current_dns_lbl.pack(anchor="w", padx=14, pady=(2, 2))
        self.current_dns_sub = ctk.CTkLabel(c2, text="Provider: Probing...", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        self.current_dns_sub.pack(anchor="w", padx=14, pady=(0, 8))

        # Card 3: Live Latency & Health
        c3 = ctk.CTkFrame(deck_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        c3.grid(row=0, column=2, padx=6, sticky="nsew", pady=4)
        self.c3_title = ctk.CTkLabel(c3, text="⚡ LIVE LATENCY & HEALTH", font=ctk.CTkFont(size=11, weight="bold"), text_color="#64748b")
        self.c3_title.pack(anchor="w", padx=14, pady=(10, 2))
        self.latency_lbl = ctk.CTkLabel(
            c3,
            text="-- ms",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color="#10b981"
        )
        self.latency_lbl.pack(anchor="w", padx=14, pady=(2, 2))
        self.health_sub_lbl = ctk.CTkLabel(c3, text="Health: Initializing...", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        self.health_sub_lbl.pack(anchor="w", padx=14, pady=(0, 8))

        # Card 4: Sentinel Metrics
        c4 = ctk.CTkFrame(deck_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        c4.grid(row=0, column=3, padx=(6, 0), sticky="nsew", pady=4)
        self.c4_title = ctk.CTkLabel(c4, text="🛡️ SENTINEL METRICS", font=ctk.CTkFont(size=11, weight="bold"), text_color="#64748b")
        self.c4_title.pack(anchor="w", padx=14, pady=(10, 2))
        self.metric_failovers_lbl = ctk.CTkLabel(
            c4,
            text="0 Failovers",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color="#38bdf8"
        )
        self.metric_failovers_lbl.pack(anchor="w", padx=14, pady=(2, 2))
        self.metric_uptime_lbl = ctk.CTkLabel(c4, text="Checks: 0 • Uptime: 00:00:00", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        self.metric_uptime_lbl.pack(anchor="w", padx=14, pady=(0, 8))

    def _build_tabs(self, parent):
        self.tabview = ctk.CTkTabview(
            parent,
            fg_color="#0f172a",
            segmented_button_fg_color="#1e293b",
            segmented_button_selected_color="#0284c7"
        )
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(6, 12))

        self.tab_live = self.tabview.add("📊 Live Monitor & Graphs")
        self.tab_benchmark = self.tabview.add("🚀 DNS Benchmark & Server Hub")
        self.tab_manual = self.tabview.add("🔧 Adapter & Manual DNS")
        self.tab_settings = self.tabview.add("⚙️ Settings & Policies")

        self._build_tab_live(self.tab_live)
        self._build_tab_benchmark(self.tab_benchmark)
        self._build_tab_manual(self.tab_manual)
        self._build_tab_settings(self.tab_settings)

    # ---------- TAB 1: LIVE MONITOR & QUICK ACTIONS ----------
    def _build_tab_live(self, parent):
        btn_bar = ctk.CTkFrame(parent, fg_color="transparent")
        btn_bar.pack(fill="x", padx=10, pady=(6, 8))

        self.btn_quick_fix = ctk.CTkButton(
            btn_bar,
            text="⚡ Optimize to Fastest DNS",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.quick_optimize_async,
            height=34
        )
        self.btn_quick_fix.pack(side="left", padx=(0, 8))

        self.btn_flush = ctk.CTkButton(
            btn_bar,
            text="🧹 Flush DNS Cache",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self.flush_dns_action,
            height=34
        )
        self.btn_flush.pack(side="left", padx=8)

        self.btn_dhcp = ctk.CTkButton(
            btn_bar,
            text="🔄 Reset to DHCP",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            command=self.reset_dhcp_action,
            height=34
        )
        self.btn_dhcp.pack(side="left", padx=8)

        self.btn_copy_dns = ctk.CTkButton(
            btn_bar,
            text="📋 Copy DNS Info",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            command=self.copy_dns_to_clipboard,
            height=34
        )
        self.btn_copy_dns.pack(side="left", padx=8)

        self.btn_clear_log = ctk.CTkButton(
            btn_bar,
            text="Clear Log",
            width=76,
            fg_color="#1e293b",
            hover_color="#334155",
            command=self.clear_logs,
            height=34
        )
        self.btn_clear_log.pack(side="right")

        # Real-time Latency Sparkline Graph
        self.graph_widget = LatencyGraphCanvas(parent)
        self.graph_widget.pack(fill="x", padx=10, pady=(0, 6))

        # Log Filter Bar
        log_header = ctk.CTkFrame(parent, fg_color="transparent")
        log_header.pack(fill="x", padx=10, pady=(4, 2))

        self.log_section_title = ctk.CTkLabel(
            log_header,
            text="📋 REAL-TIME SENTINEL ACTIVITY LOG",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#64748b"
        )
        self.log_section_title.pack(side="left")

        filter_box = ctk.CTkFrame(log_header, fg_color="transparent")
        filter_box.pack(side="right")

        filters = [
            ("all", "All"),
            ("success", "Success"),
            ("warning", "Alerts"),
            ("failover", "Failover"),
            ("error", "Errors")
        ]
        for lvl, label in filters:
            ctk.CTkButton(
                filter_box,
                text=label,
                width=64,
                height=22,
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#1e293b",
                hover_color="#334155",
                command=lambda l=lvl: self.filter_logs(l)
            ).pack(side="left", padx=2)

        # Monospace Terminal View
        self.log_box = ctk.CTkTextbox(
            parent,
            fg_color="#060911",
            text_color="#e2e8f0",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=8,
            border_width=1,
            border_color="#1e293b"
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.log_box.tag_config("success", foreground="#34d399")
        self.log_box.tag_config("warning", foreground="#fbbf24")
        self.log_box.tag_config("error", foreground="#f87171")
        self.log_box.tag_config("failover", foreground="#38bdf8")
        self.log_box.tag_config("info", foreground="#94a3b8")

    # ---------- TAB 2: DNS BENCHMARK & SERVER HUB ----------
    def _build_tab_benchmark(self, parent):
        top_bar = ctk.CTkFrame(parent, fg_color="transparent")
        top_bar.pack(fill="x", padx=10, pady=(6, 6))

        self.search_entry = ctk.CTkEntry(
            top_bar,
            placeholder_text="🔍 Filter by name, IP, or keyword...",
            width=260,
            height=32,
            fg_color="#1e293b",
            border_color="#334155"
        )
        self.search_entry.pack(side="left", padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", self.on_search_key)

        self.btn_add_custom = ctk.CTkButton(
            top_bar,
            text="+ Add Custom DNS",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            command=self.open_add_custom_dns_modal,
            height=32
        )
        self.btn_add_custom.pack(side="left", padx=4)

        self.btn_run_bench = ctk.CTkButton(
            top_bar,
            text="🚀 Benchmark All DNS",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.run_benchmark_async,
            height=32
        )
        self.btn_run_bench.pack(side="right")

        # Benchmark Progress Indicator Bar (hidden by default)
        self.bench_prog_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=6)
        self.bench_prog_lbl = ctk.CTkLabel(
            self.bench_prog_frame,
            text="Benchmarking All Servers...",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#38bdf8"
        )
        self.bench_prog_lbl.pack(side="left", padx=12, pady=4)
        self.bench_prog_bar = ctk.CTkProgressBar(self.bench_prog_frame, width=320, height=12, progress_color="#0284c7")
        self.bench_prog_bar.set(0)
        self.bench_prog_bar.pack(side="right", padx=12, pady=6)

        # Category Filter Bar
        cat_bar = ctk.CTkFrame(parent, fg_color="transparent")
        cat_bar.pack(fill="x", padx=10, pady=(0, 6))

        categories = [
            ("All", "All Providers"),
            ("Ultra Fast", "🚀 Ultra Fast"),
            ("Security", "🛡️ Security"),
            ("Ad-Blocking", "🚫 Ad-Blocking"),
            ("Privacy", "🔒 Privacy"),
            ("Family Safe", "👨‍👩‍👦 Family Safe"),
            ("Custom", "⭐ Custom")
        ]

        self.cat_buttons = {}
        for cat_id, cat_title in categories:
            btn = ctk.CTkButton(
                cat_bar,
                text=cat_title,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0284c7" if cat_id == "All" else "#1e293b",
                hover_color="#0369a1",
                command=lambda c=cat_id: self.select_category_filter(c)
            )
            btn.pack(side="left", padx=3)
            self.cat_buttons[cat_id] = btn

        # Scrollable DNS Server Catalog
        self.bench_scroll = ctk.CTkScrollableFrame(parent, fg_color="#080d1a", corner_radius=8)
        self.bench_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.render_dns_pool_items()

    def select_category_filter(self, category_id: str):
        self.active_category = category_id
        for cid, btn in self.cat_buttons.items():
            btn.configure(fg_color="#0284c7" if cid == category_id else "#1e293b")
        self.render_dns_pool_items()

    def on_search_key(self, event):
        self.search_filter_text = self.search_entry.get().strip().lower()
        self.render_dns_pool_items()

    def render_dns_pool_items(self):
        for widget in self.bench_scroll.winfo_children():
            widget.destroy()

        pool = self.config.get("dns_pool", [])
        current_ips = self.monitor.current_dns_list

        filtered = []
        for item in pool:
            if self.active_category != "All":
                if self.active_category == "Custom" and not item.get("is_custom", False):
                    continue
                elif self.active_category != "Custom" and item.get("category") != self.active_category:
                    continue

            if self.search_filter_text:
                haystack = f"{item['name']} {item['primary']} {item.get('secondary', '')} {item.get('desc', '')} {item.get('category', '')}".lower()
                if self.search_filter_text not in haystack:
                    continue

            filtered.append(item)

        if not filtered:
            ctk.CTkLabel(
                self.bench_scroll,
                text="No DNS servers match your search criteria.",
                font=ctk.CTkFont(size=13),
                text_color="#64748b"
            ).pack(pady=40)
            return

        for entry in filtered:
            is_currently_active = (entry["primary"] in current_ips)

            border_c = "#10b981" if is_currently_active else "#1e293b"
            border_w = 2 if is_currently_active else 1

            row_frame = ctk.CTkFrame(
                self.bench_scroll,
                fg_color="#0f172a",
                corner_radius=8,
                border_width=border_w,
                border_color=border_c
            )
            row_frame.pack(fill="x", pady=4, padx=4)

            # Left Details: Provider Info
            left_f = ctk.CTkFrame(row_frame, fg_color="transparent")
            left_f.pack(side="left", padx=14, pady=10, fill="x", expand=True)

            title_row = ctk.CTkFrame(left_f, fg_color="transparent")
            title_row.pack(anchor="w")

            name_lbl = ctk.CTkLabel(
                title_row,
                text=entry["name"],
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color="#f8fafc"
            )
            name_lbl.pack(side="left")

            cat_tag = ctk.CTkLabel(
                title_row,
                text=entry.get("category", "Public"),
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#1e293b",
                text_color="#38bdf8",
                corner_radius=4,
                padx=6,
                pady=1
            )
            cat_tag.pack(side="left", padx=(8, 0))

            if is_currently_active:
                active_badge = ctk.CTkLabel(
                    title_row,
                    text="✓ ACTIVE CURRENT",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    fg_color="#064e3b",
                    text_color="#34d399",
                    corner_radius=4,
                    padx=8,
                    pady=1
                )
                active_badge.pack(side="left", padx=(8, 0))

            ips_text = f"Primary: {entry['primary']}   |   Secondary: {entry.get('secondary', 'None')}"
            ip_lbl = ctk.CTkLabel(
                left_f,
                text=ips_text,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color="#60a5fa"
            )
            ip_lbl.pack(anchor="w", pady=(2, 2))

            desc_lbl = ctk.CTkLabel(
                left_f,
                text=entry.get("desc", ""),
                font=ctk.CTkFont(size=11),
                text_color="#94a3b8"
            )
            desc_lbl.pack(anchor="w")

            # Right Controls: Ping Badge, Test Button, Apply Action
            right_f = ctk.CTkFrame(row_frame, fg_color="transparent")
            right_f.pack(side="right", padx=14, pady=10)

            matching = next((b for b in self.benchmarks_data if b["name"] == entry["name"]), None)
            if matching:
                if matching["is_alive"]:
                    ms = matching["latency_ms"]
                    badge_color = "#064e3b" if ms < 40 else ("#78350f" if ms < 100 else "#334155")
                    text_color = "#34d399" if ms < 40 else ("#f59e0b" if ms < 100 else "#cbd5e1")
                    ping_text = f"{ms} ms"
                else:
                    badge_color = "#450a0a"
                    text_color = "#f87171"
                    ping_text = "TIMEOUT"
            else:
                badge_color = "#1e293b"
                text_color = "#94a3b8"
                ping_text = "Untested"

            ping_badge = ctk.CTkLabel(
                right_f,
                text=ping_text,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                fg_color=badge_color,
                text_color=text_color,
                corner_radius=6,
                padx=10,
                pady=4,
                width=90
            )
            ping_badge.pack(side="left", padx=(0, 6))

            test_btn = ctk.CTkButton(
                right_f,
                text="Test",
                width=58,
                height=30,
                fg_color="#1e293b",
                hover_color="#334155",
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda e=entry, b=ping_badge: self.test_single_dns_async(e, b)
            )
            test_btn.pack(side="left", padx=(0, 6))

            apply_btn = ctk.CTkButton(
                right_f,
                text="Apply",
                width=72,
                height=30,
                fg_color="#0284c7",
                hover_color="#0369a1",
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda e=entry: self.apply_specific_dns(e)
            )
            apply_btn.pack(side="left")

            if entry.get("is_custom", False):
                del_btn = ctk.CTkButton(
                    right_f,
                    text="🗑️",
                    width=32,
                    height=30,
                    fg_color="#334155",
                    hover_color="#ef4444",
                    command=lambda e=entry: self.delete_custom_dns(e)
                )
                del_btn.pack(side="left", padx=(6, 0))

    def test_single_dns_async(self, entry: Dict, badge_lbl: ctk.CTkLabel):
        badge_lbl.configure(text="...", fg_color="#1e293b", text_color="#38bdf8")

        def _worker():
            res = DNSCore.benchmark_single_server(entry, timeout=1.5)
            existing = next((i for i, b in enumerate(self.benchmarks_data) if b["name"] == entry["name"]), None)
            if existing is not None:
                self.benchmarks_data[existing] = res
            else:
                self.benchmarks_data.append(res)

            def _update_badge():
                if res["is_alive"]:
                    ms = res["latency_ms"]
                    badge_lbl.configure(
                        text=f"{ms} ms",
                        fg_color="#064e3b" if ms < 40 else ("#78350f" if ms < 100 else "#334155"),
                        text_color="#34d399" if ms < 40 else ("#f59e0b" if ms < 100 else "#cbd5e1")
                    )
                else:
                    badge_lbl.configure(text="TIMEOUT", fg_color="#450a0a", text_color="#f87171")

            self._safe_call(_update_badge)

        threading.Thread(target=_worker, daemon=True).start()

    # ---------- TAB 3: ADAPTER & MANUAL SETUP ----------
    def _build_tab_manual(self, parent):
        scroll_m = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll_m.pack(fill="both", expand=True, padx=10, pady=8)

        # Section 1: Network Adapter Specifications
        s1 = ctk.CTkFrame(scroll_m, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        s1.pack(fill="x", pady=6)
        ctk.CTkLabel(
            s1,
            text="📡 NETWORK ADAPTER SPECIFICATIONS",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 6))

        self.adapter_specs_lbl = ctk.CTkLabel(
            s1,
            text="Gathering adapter hardware specifications...",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#cbd5e1",
            justify="left"
        )
        self.adapter_specs_lbl.pack(anchor="w", padx=16, pady=(0, 12))

        # Section 2: Advanced Diagnostic & Repair Toolkit
        s_tools = ctk.CTkFrame(scroll_m, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        s_tools.pack(fill="x", pady=6)
        ctk.CTkLabel(
            s_tools,
            text="🛠️ ADVANCED NETWORK DIAGNOSTIC & REPAIR",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 6))

        tools_bar = ctk.CTkFrame(s_tools, fg_color="transparent")
        tools_bar.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkButton(
            tools_bar,
            text="🔄 Repair Network Stack (Winsock/ARP)",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.repair_network_stack_action,
            height=32
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            tools_bar,
            text="🧹 Flush DNS Cache",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self.flush_dns_action,
            height=32
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            tools_bar,
            text="🔄 Reset to DHCP",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            command=self.reset_dhcp_action,
            height=32
        ).pack(side="left", padx=8)

        # Section 3: Manual DNS IPv4 Assignment
        s2 = ctk.CTkFrame(scroll_m, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        s2.pack(fill="x", pady=6)
        ctk.CTkLabel(
            s2,
            text="✍️ CONFIGURE CUSTOM IPV4 DNS MANUALLY",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 6))

        form_f = ctk.CTkFrame(s2, fg_color="transparent")
        form_f.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(form_f, text="Preferred DNS Server (Primary IPv4):", font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="w", pady=4)
        self.manual_pri_entry = ctk.CTkEntry(form_f, width=280, placeholder_text="e.g. 1.1.1.1", fg_color="#1e293b", border_color="#334155")
        self.manual_pri_entry.grid(row=0, column=1, padx=12, pady=4, sticky="w")

        ctk.CTkLabel(form_f, text="Alternate DNS Server (Secondary IPv4):", font=ctk.CTkFont(size=11, weight="bold")).grid(row=1, column=0, sticky="w", pady=4)
        self.manual_sec_entry = ctk.CTkEntry(form_f, width=280, placeholder_text="e.g. 1.0.0.1", fg_color="#1e293b", border_color="#334155")
        self.manual_sec_entry.grid(row=1, column=1, padx=12, pady=4, sticky="w")

        btn_manual_apply = ctk.CTkButton(
            form_f,
            text="Apply Manual DNS",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.apply_manual_dns,
            height=32
        )
        btn_manual_apply.grid(row=2, column=1, padx=12, pady=(10, 4), sticky="w")

        # Section 4: DNS Query Diagnostic Probe
        s3 = ctk.CTkFrame(scroll_m, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        s3.pack(fill="x", pady=6)
        ctk.CTkLabel(
            s3,
            text="🔍 INSTANT DOMAIN RESOLUTION TEST",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=16, pady=(12, 6))

        probe_f = ctk.CTkFrame(s3, fg_color="transparent")
        probe_f.pack(fill="x", padx=16, pady=(0, 12))

        self.probe_domain_entry = ctk.CTkEntry(probe_f, width=280, placeholder_text="e.g. google.com", fg_color="#1e293b", border_color="#334155")
        self.probe_domain_entry.insert(0, "google.com")
        self.probe_domain_entry.pack(side="left")

        self.btn_probe = ctk.CTkButton(
            probe_f,
            text="Test Resolution",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self.run_domain_probe,
            height=30
        )
        self.btn_probe.pack(side="left", padx=12)

        self.probe_result_lbl = ctk.CTkLabel(s3, text="", font=ctk.CTkFont(family="Consolas", size=11), text_color="#34d399")
        self.probe_result_lbl.pack(anchor="w", padx=16, pady=(0, 10))

    # ---------- TAB 4: SETTINGS & POLICIES ----------
    def _build_tab_settings(self, parent):
        scroll_settings = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll_settings.pack(fill="both", expand=True, padx=10, pady=6)

        # 1. Automatic Failover Switch
        f1 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f1.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f1,
            text="Enable Automatic Failover\nAutomatically switch to fastest verified DNS when current server fails",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        self.switch_auto_failover = ctk.CTkSwitch(f1, text="", command=self.save_settings_from_ui, progress_color="#0284c7")
        if self.config.get("auto_switch_enabled", True):
            self.switch_auto_failover.select()
        self.switch_auto_failover.pack(side="right", padx=16)

        # 2. Check Frequency
        f2 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f2.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f2,
            text="Health Check Interval\nFrequency of background DNS uptime probing (Seconds)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        cur_interval = str(self.config.get("check_interval_seconds", 6))
        self.opt_interval = ctk.CTkOptionMenu(
            f2,
            values=["3", "6", "10", "15", "30"],
            command=lambda v: self.save_settings_from_ui(),
            fg_color="#1e293b",
            button_color="#334155"
        )
        self.opt_interval.set(cur_interval)
        self.opt_interval.pack(side="right", padx=16)

        # 3. Fail Threshold
        f3 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f3.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f3,
            text="Failover Threshold\nConsecutive unanswered queries before emergency failover is triggered",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        cur_threshold = str(self.config.get("fail_threshold", 2))
        self.opt_threshold = ctk.CTkOptionMenu(
            f3,
            values=["1", "2", "3", "5"],
            command=lambda v: self.save_settings_from_ui(),
            fg_color="#1e293b",
            button_color="#334155"
        )
        self.opt_threshold.set(cur_threshold)
        self.opt_threshold.pack(side="right", padx=16)

        # 4. Windows Startup
        f4 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f4.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f4,
            text="Launch with Windows\nStart DNS Shield Pro silently in the background at system startup",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        self.switch_autostart = ctk.CTkSwitch(f4, text="", command=self.toggle_autostart, progress_color="#0284c7")
        if ConfigManager.is_auto_start_enabled():
            self.switch_autostart.select()
        self.switch_autostart.pack(side="right", padx=16)

        # 5. Minimize to Tray on Close
        f5 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f5.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f5,
            text="Minimize to System Tray\nClosing the window sends the application to notification area",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        self.switch_tray = ctk.CTkSwitch(f5, text="", command=self.save_settings_from_ui, progress_color="#0284c7")
        if self.config.get("minimize_to_tray", True):
            self.switch_tray.select()
        self.switch_tray.pack(side="right", padx=16)

        # 6. Notifications on Switch
        f6 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f6.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f6,
            text="Desktop Notifications\nDisplay Windows notifications when automatic failover occurs",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc",
            justify="left"
        ).pack(side="left", padx=16, pady=12)
        self.switch_notify = ctk.CTkSwitch(f6, text="", command=self.save_settings_from_ui, progress_color="#0284c7")
        if self.config.get("notify_on_switch", True):
            self.switch_notify.select()
        self.switch_notify.pack(side="right", padx=16)

        # 7. Test Domains Editor
        f7 = ctk.CTkFrame(scroll_settings, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        f7.pack(fill="x", pady=5)
        ctk.CTkLabel(
            f7,
            text="Target Test Domains (Comma separated):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f8fafc"
        ).pack(anchor="w", padx=16, pady=(12, 4))
        domains_val = ", ".join(self.config.get("test_domains", ["google.com", "cloudflare.com"]))
        self.entry_domains = ctk.CTkEntry(f7, width=440, fg_color="#1e293b", border_color="#334155")
        self.entry_domains.insert(0, domains_val)
        self.entry_domains.pack(anchor="w", padx=16, pady=(0, 12))

        btn_save_domains = ctk.CTkButton(
            f7,
            text="Save Test Domains",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.save_settings_from_ui,
            height=28
        )
        btn_save_domains.pack(anchor="w", padx=16, pady=(0, 12))

    # ==================== LOGIC & CONTROLS ====================
    def refresh_adapters(self):
        try:
            self.adapters_list = DNSCore.get_network_adapters()
            active_names = [a["name"] for a in self.adapters_list if a["is_up"]]
            if not active_names:
                active_names = [a["name"] for a in self.adapters_list]

            auto_str = "Auto-Detect (Primary)"
            display_values = [auto_str] + active_names
            self.adapter_dropdown.configure(values=display_values)

            saved = self.config.get("selected_adapter", "Auto")
            if saved == "Auto" or saved not in active_names:
                self.adapter_dropdown.set(auto_str)
            else:
                self.adapter_dropdown.set(saved)

            self._update_adapter_specs()
        except Exception as e:
            print(f"[GUI] Error refreshing network adapters: {e}")

    def _update_adapter_specs(self):
        sel = self.monitor.get_selected_adapter()
        matching = next((a for a in self.adapters_list if a["name"] == sel), None)
        if matching:
            specs = (
                f"Interface Name:      {matching['name']}\n"
                f"Description:         {matching['desc']}\n"
                f"Operational Status:  {matching['status']} ({'Connected' if matching['is_up'] else 'Disconnected'})\n"
                f"Link Speed:          {matching.get('link_speed', 'N/A')}\n"
                f"Hardware MAC:        {matching.get('mac', 'N/A')}\n"
                f"Active IPv4 DNS:     {', '.join(matching['current_dns']) if matching['current_dns'] else 'DHCP (Automatic / ISP Default)'}"
            )
        else:
            specs = f"Interface: {sel}\nStatus: Gathering network parameters..."
        self.adapter_specs_lbl.configure(text=specs)

    def on_adapter_selected(self, val):
        if val == "Auto-Detect (Primary)":
            self.config.set("selected_adapter", "Auto")
        else:
            self.config.set("selected_adapter", val)
        self.monitor.log(f"Active network adapter preference set to: {val}", "info")
        self._update_adapter_specs()

    def toggle_protection(self):
        if self.protection_switch.get() == 1:
            self.monitor.start()
            self.status_badge.configure(text="● PROTECTED", fg_color="#064e3b", text_color="#34d399")
        else:
            self.monitor.stop()
            self.status_badge.configure(text="● PAUSED", fg_color="#450a0a", text_color="#f87171")

    def tray_toggle_protection(self, enable: bool):
        if enable:
            self._safe_call(lambda: self.protection_switch.select())
            self.monitor.start()
            self._safe_call(lambda: self.status_badge.configure(text="● PROTECTED", fg_color="#064e3b", text_color="#34d399"))
        else:
            self._safe_call(lambda: self.protection_switch.deselect())
            self.monitor.stop()
            self._safe_call(lambda: self.status_badge.configure(text="● PAUSED", fg_color="#450a0a", text_color="#f87171"))

    def quick_optimize_async(self):
        threading.Thread(target=self._quick_optimize_worker, daemon=True).start()

    def _quick_optimize_worker(self):
        self._safe_call(lambda: self.btn_quick_fix.configure(state="disabled", text="⏳ Benchmarking..."))
        res = self.monitor.force_quick_optimize()
        if res.get("benchmarks"):
            self.benchmarks_data = res["benchmarks"]
            self._safe_call(self.render_dns_pool_items)
            self._safe_call(lambda: self.show_toast(f"✓ Optimized to fastest DNS: {res.get('best', {}).get('name', 'DNS')}"))
        self._safe_call(lambda: self.btn_quick_fix.configure(state="normal", text="⚡ Optimize to Fastest DNS"))

    def flush_dns_action(self):
        success, msg = DNSCore.flush_dns()
        if success:
            self.monitor.log("Windows DNS cache flushed instantly (native ctypes DnsFlushResolverCache).", "success")
            self.show_toast("✓ Windows DNS cache flushed instantly (0.1 ms)")
        else:
            self.monitor.log(f"DNS flush notice: {msg}", "error")

    def reset_dhcp_action(self):
        adapter = self.monitor.get_selected_adapter()
        ok, msg = DNSCore.reset_adapter_dns_to_dhcp(adapter)
        if ok:
            self.monitor.log(f"Reset {adapter} DNS configuration to Automatic (DHCP / ISP default).", "info")
            self.refresh_adapters()
            self.show_toast("✓ Network adapter reset to DHCP / ISP default")
        else:
            self._check_admin_error(msg)

    def repair_network_stack_action(self):
        ok, msg = DNSCore.repair_network_stack()
        self.monitor.log(f"Network Stack Repair: {msg}", "success" if ok else "error")
        self.show_toast("✓ Network stack and ARP table purged successfully")

    def apply_specific_dns(self, entry: Dict):
        adapter = self.monitor.get_selected_adapter()
        pri = entry["primary"]
        sec = entry.get("secondary", "")
        self.monitor.log(f"Applying: {entry['name']} [{pri}, {sec}] on {adapter}...", "info")

        def _worker():
            ok, msg = DNSCore.set_adapter_dns(adapter, pri, sec)
            if ok:
                self.monitor.log(f"{entry['name']} configured successfully! DNS cache cleared.", "success")
                self._safe_call(self.refresh_adapters)
                self._safe_call(self.render_dns_pool_items)
                self._safe_call(lambda: self.show_toast(f"✓ Configured DNS: {entry['name']}"))
            else:
                self._safe_call(lambda: self._check_admin_error(msg))

        threading.Thread(target=_worker, daemon=True).start()

    def apply_manual_dns(self):
        pri = self.manual_pri_entry.get().strip()
        sec = self.manual_sec_entry.get().strip()

        # Validate IPv4 format
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if not pri or not re.match(ip_regex, pri):
            messagebox.showerror("Invalid IPv4 Address", "Please enter a valid Preferred (Primary) IPv4 address (e.g. 1.1.1.1).")
            return
        if sec and not re.match(ip_regex, sec):
            messagebox.showerror("Invalid IPv4 Address", "Alternate (Secondary) DNS IPv4 address format is invalid.")
            return

        adapter = self.monitor.get_selected_adapter()
        self.monitor.log(f"Applying manual DNS [{pri}, {sec}] on {adapter}...", "info")

        def _worker():
            ok, msg = DNSCore.set_adapter_dns(adapter, pri, sec)
            if ok:
                self.monitor.log(f"Manual DNS configured successfully on {adapter}.", "success")
                self._safe_call(self.refresh_adapters)
                self._safe_call(self.render_dns_pool_items)
                self._safe_call(lambda: self.show_toast(f"✓ Configured manual DNS: {pri}"))
            else:
                self._safe_call(lambda: self._check_admin_error(msg))

        threading.Thread(target=_worker, daemon=True).start()

    def run_domain_probe(self):
        domain = self.probe_domain_entry.get().strip()
        if not domain:
            return
        self.btn_probe.configure(state="disabled", text="Testing...")

        def _worker():
            ok, ms, info = DNSCore.test_current_dns_health(test_domains=[domain], timeout=2.0)
            def _update():
                self.btn_probe.configure(state="normal", text="Test Resolution")
                if ok:
                    self.probe_result_lbl.configure(text=f"✓ Resolved '{domain}' in {ms} ms ({info})", text_color="#34d399")
                else:
                    self.probe_result_lbl.configure(text=f"✗ Resolution failed for '{domain}' ({info})", text_color="#f87171")
            self._safe_call(_update)

        threading.Thread(target=_worker, daemon=True).start()

    def run_benchmark_async(self):
        threading.Thread(target=self._benchmark_worker, daemon=True).start()

    def _benchmark_worker(self):
        self._safe_call(lambda: self.btn_run_bench.configure(state="disabled", text="⏳ Benchmarking..."))
        self._safe_call(lambda: self.bench_prog_frame.pack(fill="x", padx=10, pady=(0, 6)))
        self._safe_call(lambda: self.bench_prog_bar.set(0))

        pool = self.config.get("dns_pool", [])
        total = len(pool)

        def _on_prog(done, tot, latest):
            pct = done / tot if tot else 1.0
            def _u():
                self.bench_prog_bar.set(pct)
                self.bench_prog_lbl.configure(
                    text=f"Benchmark: {done}/{tot} completed ({latest['name']}: {latest['latency_ms']} ms)"
                )
            self._safe_call(_u)

        self.benchmarks_data = DNSCore.benchmark_all_servers(pool, timeout=1.5, progress_callback=_on_prog)
        self.monitor.log(f"Benchmark finished. {len(self.benchmarks_data)} servers tested.", "success")

        def _done():
            self.bench_prog_frame.pack_forget()
            self.render_dns_pool_items()
            self.btn_run_bench.configure(state="normal", text="🚀 Benchmark All DNS")
            self.show_toast(f"✓ {len(self.benchmarks_data)} DNS servers benchmarked successfully.")

        self._safe_call(_done)

    def copy_dns_to_clipboard(self):
        dns_str = " | ".join(self.monitor.current_dns_list) if self.monitor.current_dns_list else "DHCP Default"
        self.root.clipboard_clear()
        self.root.clipboard_append(dns_str)
        self.show_toast(f"📋 Copied: {dns_str}")

    def _check_admin_error(self, err_msg: str):
        self.monitor.log(f"DNS Modification Failed: {err_msg}", "error")
        if not self.is_admin:
            ask = messagebox.askyesno(
                "Administrator Rights Required",
                "Modifying Windows network adapter settings requires Administrator privileges.\n\n"
                "Would you like to restart DNS Shield Pro with Administrator privileges now?"
            )
            if ask and self.run_as_admin_func:
                self.run_as_admin_func()

    def request_elevation(self):
        if self.run_as_admin_func:
            self.run_as_admin_func()

    def open_add_custom_dns_modal(self):
        modal = ctk.CTkToplevel(self.root)
        modal.title("Add Custom DNS")
        modal.geometry("450x400")
        modal.resizable(False, False)
        modal.transient(self.root)
        modal.grab_set()

        ctk.CTkLabel(modal, text="Add Custom DNS Provider", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(16, 12))

        f = ctk.CTkFrame(modal, fg_color="transparent")
        f.pack(fill="both", expand=True, padx=20)

        ctk.CTkLabel(f, text="Provider / Resolver Name:").pack(anchor="w")
        e_name = ctk.CTkEntry(f, placeholder_text="e.g. Home Pi-hole or Corporate Resolver", width=390)
        e_name.pack(pady=(2, 8))

        ctk.CTkLabel(f, text="Primary IPv4 Address:").pack(anchor="w")
        e_pri = ctk.CTkEntry(f, placeholder_text="e.g. 192.168.1.50", width=390)
        e_pri.pack(pady=(2, 8))

        ctk.CTkLabel(f, text="Secondary IPv4 Address (Optional):").pack(anchor="w")
        e_sec = ctk.CTkEntry(f, placeholder_text="e.g. 192.168.1.51", width=390)
        e_sec.pack(pady=(2, 8))

        ctk.CTkLabel(f, text="Description:").pack(anchor="w")
        e_desc = ctk.CTkEntry(f, placeholder_text="e.g. Local network DNS with ad-blocking", width=390)
        e_desc.pack(pady=(2, 12))

        def _save():
            name = e_name.get().strip()
            pri = e_pri.get().strip()
            sec = e_sec.get().strip()
            desc = e_desc.get().strip()

            ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            if not name or not pri or not re.match(ip_regex, pri):
                messagebox.showerror("Invalid Information", "Please enter a valid Provider Name and Primary IPv4 address.", parent=modal)
                return
            if sec and not re.match(ip_regex, sec):
                messagebox.showerror("Invalid Information", "Secondary IPv4 address format is invalid.", parent=modal)
                return

            success = self.config.add_custom_dns(name=name, primary=pri, secondary=sec, category="Custom", desc=desc)
            if success:
                self.monitor.log(f"Added custom DNS: {name} ({pri})", "success")
                self.render_dns_pool_items()
                self.show_toast(f"✓ Added custom DNS: {name}")
                modal.destroy()

        ctk.CTkButton(modal, text="Save DNS Provider", fg_color="#0284c7", command=_save, width=170, height=32).pack(pady=(0, 16))

    def delete_custom_dns(self, entry: Dict):
        pri = entry["primary"]
        name = entry["name"]
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to remove '{name}' ({pri}) from your catalog?"):
            self.config.remove_custom_dns(pri)
            self.monitor.log(f"Removed custom DNS: {name}", "info")
            self.render_dns_pool_items()
            self.show_toast(f"✓ Removed: {name}")

    def save_settings_from_ui(self):
        self.config.set("auto_switch_enabled", bool(self.switch_auto_failover.get() == 1))
        self.config.set("check_interval_seconds", int(self.opt_interval.get()))
        self.config.set("fail_threshold", int(self.opt_threshold.get()))
        self.config.set("minimize_to_tray", bool(self.switch_tray.get() == 1))
        self.config.set("notify_on_switch", bool(self.switch_notify.get() == 1))

        raw_domains = self.entry_domains.get()
        parsed = [d.strip() for d in raw_domains.split(",") if d.strip()]
        if parsed:
            self.config.set("test_domains", parsed)

        self.monitor.log("Settings saved and updated successfully.", "info")
        self.show_toast("✓ Settings saved successfully")

    def toggle_autostart(self):
        enabled = (self.switch_autostart.get() == 1)
        ConfigManager.set_auto_start(enabled)
        if enabled:
            self.monitor.log("Windows startup integration enabled.", "info")
            self.show_toast("✓ Launch with Windows enabled")
        else:
            self.monitor.log("Windows startup integration disabled.", "info")
            self.show_toast("✓ Launch with Windows disabled")

    def clear_logs(self):
        self.raw_logs.clear()
        self.log_box.delete("1.0", "end")

    def filter_logs(self, level: str):
        self.log_filter_level = level
        self.log_box.delete("1.0", "end")
        for item in self.raw_logs:
            if level == "all" or item["level"] == level:
                self.log_box.insert("end", item["text"] + "\n", item["level"])
        self.log_box.see("end")

    # ==================== CALLBACK LISTENERS ====================
    def _on_monitor_status(self, data: Dict):
        def _update():
            if "history" in data:
                self.graph_widget.update_data(data["history"])

            self.adapter_sub_lbl.configure(text=f"Interface: {data['adapter']}")

            dns_str = " | ".join(data["dns_list"]) if data["dns_list"] else "DHCP (Automatic / ISP Default)"
            self.current_dns_lbl.configure(text=dns_str)

            provider_name = self._guess_provider_name(data["dns_list"])
            self.current_dns_sub.configure(text=f"Provider: {provider_name}")

            code = data["status_code"]
            lat = data["latency_ms"]

            if code == "ok":
                badge_color = "#10b981" if lat < 40 else ("#f59e0b" if lat < 100 else "#cbd5e1")
                self.latency_lbl.configure(text=f"{lat} ms", text_color=badge_color)
                health_text = "Ultra Fast (< 40ms)" if lat < 40 else ("Good Latency" if lat < 100 else "Acceptable")
                self.health_sub_lbl.configure(text=f"Health: {health_text}", text_color="#10b981")
                self.tray.update_status("ok", f"DNS Shield Pro: {lat} ms (Protected)")
            elif code == "offline":
                self.latency_lbl.configure(text="DISCONNECTED", text_color="#ef4444")
                self.health_sub_lbl.configure(text="Health: Network Cable / Wi-Fi Disconnected", text_color="#ef4444")
                self.tray.update_status("offline", "DNS Shield Pro: Network Offline")
            elif code == "warning":
                self.latency_lbl.configure(text="TIMEOUT", text_color="#f59e0b")
                self.health_sub_lbl.configure(text=f"Health: No Response ({data['fails']}/{data['threshold']})", text_color="#f59e0b")
                self.tray.update_status("warning", "DNS Shield Pro: Query Timeout")
            elif code == "switching":
                self.latency_lbl.configure(text="SWITCHING", text_color="#38bdf8")
                self.health_sub_lbl.configure(text="Health: Executing Emergency Failover...", text_color="#38bdf8")
                self.tray.update_status("warning", "DNS Shield Pro: Failover Active...")
            elif code == "error":
                self.latency_lbl.configure(text="OFFLINE", text_color="#ef4444")
                self.health_sub_lbl.configure(text="Health: DNS Service Down!", text_color="#ef4444")
                self.tray.update_status("error", "DNS Shield Pro: DNS Offline")
            elif code == "stopped":
                self.latency_lbl.configure(text="PAUSED", text_color="#64748b")
                self.health_sub_lbl.configure(text="Health: Monitoring Suspended", text_color="#64748b")

            self.metric_failovers_lbl.configure(text=f"{data.get('failovers', 0)} Failovers")
            self.metric_uptime_lbl.configure(
                text=f"Checks: {data.get('total_checks', 0)} • Uptime: {data.get('uptime', '00:00:00')}"
            )

        self._safe_call(_update)

    def _guess_provider_name(self, dns_list: List[str]) -> str:
        if not dns_list:
            return "ISP Default (DHCP)"
        pri = dns_list[0]
        pool = self.config.get("dns_pool", [])
        for entry in pool:
            if entry["primary"] == pri or entry.get("secondary") == pri:
                return entry["name"]
        return "Custom DNS"

    def _on_monitor_log(self, message: str, level: str):
        self.raw_logs.append({"text": message, "level": level})
        if len(self.raw_logs) > 600:
            self.raw_logs.pop(0)

        def _log():
            if self.log_filter_level == "all" or self.log_filter_level == level:
                try:
                    self.log_box.insert("end", message + "\n", level)
                    self.log_box.see("end")
                except Exception:
                    pass
        self._safe_call(_log)

    def _on_dns_switched(self, name: str, ip: str, latency: float):
        if self.config.get("notify_on_switch", True):
            self.tray.notify(
                "DNS Failover Successful",
                f"Connectivity restored -> {name} ({ip} - {latency} ms)"
            )

    # ==================== WINDOW & LIFECYCLE ====================
    def on_window_close(self):
        if self.config.get("minimize_to_tray", True):
            self.root.withdraw()
            self.tray.notify(
                "DNS Shield Pro",
                "Running silently in the system tray notification area."
            )
        else:
            self.full_exit()

    def show_window_from_tray(self):
        def _show():
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self.root.update()
            self.root.attributes("-topmost", False)
            self.root.lift()
            self.root.focus_force()
        self._safe_call(_show)

    def full_exit(self):
        self.monitor.stop()
        self.tray.stop()
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
        sys.exit(0)
