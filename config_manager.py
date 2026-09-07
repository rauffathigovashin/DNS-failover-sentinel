import json
import os
import winreg
import sys
from typing import List, Dict, Optional

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "DNSShieldPro"

DEFAULT_DNS_POOL: List[Dict] = [
    # --- Ultra Fast Public DNS ---
    {
        "id": "cf_main",
        "name": "Cloudflare Primary",
        "primary": "1.1.1.1",
        "secondary": "1.0.0.1",
        "category": "Ultra Fast",
        "desc": "Global lowest latency anycast network, uncensored and highly reliable.",
        "is_custom": False
    },
    {
        "id": "cf_alt",
        "name": "Cloudflare Alt (Bypass)",
        "primary": "1.0.0.1",
        "secondary": "1.1.1.1",
        "category": "Ultra Fast",
        "desc": "Alternative Cloudflare endpoint. Highly resilient when 1.1.1.1 is throttled.",
        "is_custom": False
    },
    {
        "id": "google",
        "name": "Google Public DNS",
        "primary": "8.8.8.8",
        "secondary": "8.8.4.4",
        "category": "Ultra Fast",
        "desc": "Worldwide distributed Google infrastructure with exceptional uptime.",
        "is_custom": False
    },
    {
        "id": "opendns_home",
        "name": "OpenDNS Standard (Cisco)",
        "primary": "208.67.222.222",
        "secondary": "208.67.220.220",
        "category": "Ultra Fast",
        "desc": "Enterprise-grade Cisco Anycast DNS with smart routing and high reliability.",
        "is_custom": False
    },
    {
        "id": "controld_free",
        "name": "Control D Free Fast",
        "primary": "76.76.2.0",
        "secondary": "76.76.10.0",
        "category": "Ultra Fast",
        "desc": "Modern high-speed, zero-logging Anycast DNS service.",
        "is_custom": False
    },
    {
        "id": "level3",
        "name": "Level3 / CenturyLink",
        "primary": "4.2.2.1",
        "secondary": "4.2.2.2",
        "category": "Ultra Fast",
        "desc": "Direct Tier-1 internet backbone provider infrastructure.",
        "is_custom": False
    },
    {
        "id": "gcore",
        "name": "GCore Public DNS",
        "primary": "95.85.95.85",
        "secondary": "2.56.220.2",
        "category": "Ultra Fast",
        "desc": "Global high-throughput edge network with ultra-low latency.",
        "is_custom": False
    },
    {
        "id": "alidns",
        "name": "Alibaba AliDNS",
        "primary": "223.5.5.5",
        "secondary": "223.6.6.6",
        "category": "Ultra Fast",
        "desc": "Extremely stable public DNS with vast worldwide routing.",
        "is_custom": False
    },

    # --- Security & Malware Protection ---
    {
        "id": "quad9_sec",
        "name": "Quad9 Protected",
        "primary": "9.9.9.9",
        "secondary": "149.112.112.112",
        "category": "Security",
        "desc": "Real-time threat intelligence blocking malware, phishing, and botnets.",
        "is_custom": False
    },
    {
        "id": "cf_sec",
        "name": "Cloudflare Malware Blocker",
        "primary": "1.1.1.2",
        "secondary": "1.0.0.2",
        "category": "Security",
        "desc": "Automated blocking of malicious websites via Cloudflare 1.1.1.2.",
        "is_custom": False
    },
    {
        "id": "cleanbrowsing_sec",
        "name": "CleanBrowsing Security",
        "primary": "185.228.168.9",
        "secondary": "185.228.169.9",
        "category": "Security",
        "desc": "Protects your devices from malware, phishing, and ransomware domains.",
        "is_custom": False
    },
    {
        "id": "comodo_sec",
        "name": "Comodo Secure DNS",
        "primary": "8.26.56.26",
        "secondary": "8.20.247.20",
        "category": "Security",
        "desc": "Comodo cybersecurity layer blocking malicious websites and spyware.",
        "is_custom": False
    },
    {
        "id": "controld_malware",
        "name": "Control D Malware Shield",
        "primary": "76.76.2.1",
        "secondary": "76.76.10.1",
        "category": "Security",
        "desc": "Blocks known malware, scam pages, and phishing domains.",
        "is_custom": False
    },

    # --- Ad-Blocking & Tracker Protection ---
    {
        "id": "adguard_default",
        "name": "AdGuard Default Ad-Block",
        "primary": "94.140.14.14",
        "secondary": "94.140.15.15",
        "category": "Ad-Blocking",
        "desc": "Network-level blocking of intrusive ads, trackers, and telemetry.",
        "is_custom": False
    },
    {
        "id": "controld_adblock",
        "name": "Control D Ad & Tracker Shield",
        "primary": "76.76.2.2",
        "secondary": "76.76.10.2",
        "category": "Ad-Blocking",
        "desc": "Aggressive ad and telemetry domain filtering for faster browsing.",
        "is_custom": False
    },
    {
        "id": "mullvad_adblock",
        "name": "Mullvad Ad-Block DNS",
        "primary": "194.242.2.3",
        "secondary": "193.198.108.3",
        "category": "Ad-Blocking",
        "desc": "Mullvad privacy infrastructure filtering ads and telemetry.",
        "is_custom": False
    },

    # --- Privacy & No-Log DNS ---
    {
        "id": "mullvad_privacy",
        "name": "Mullvad Privacy (No Log)",
        "primary": "194.242.2.2",
        "secondary": "193.198.108.2",
        "category": "Privacy",
        "desc": "Strict zero-logging policy based in Sweden. Uncensored and private.",
        "is_custom": False
    },
    {
        "id": "quad9_uncensored",
        "name": "Quad9 Uncensored (No Filter)",
        "primary": "9.9.9.10",
        "secondary": "149.112.112.10",
        "category": "Privacy",
        "desc": "Zero-filter DNS without threat list redirection. Pure resolution.",
        "is_custom": False
    },
    {
        "id": "dnswatch",
        "name": "DNS.WATCH Germany",
        "primary": "84.200.69.80",
        "secondary": "84.200.70.40",
        "category": "Privacy",
        "desc": "Fast European no-log DNS server with zero censorship or redirection.",
        "is_custom": False
    },
    {
        "id": "adguard_nonfiltering",
        "name": "AdGuard Non-Filtering",
        "primary": "94.140.14.140",
        "secondary": "94.140.14.141",
        "category": "Privacy",
        "desc": "Standard resolution with zero logs, censorship, or ad filtering.",
        "is_custom": False
    },

    # --- Family & Parental Control ---
    {
        "id": "cf_family",
        "name": "Cloudflare Family Safe",
        "primary": "1.1.1.3",
        "secondary": "1.0.0.3",
        "category": "Family Safe",
        "desc": "Blocks malware, spyware, and adult content automatically.",
        "is_custom": False
    },
    {
        "id": "opendns_family",
        "name": "OpenDNS FamilyShield",
        "primary": "208.67.222.123",
        "secondary": "208.67.220.123",
        "category": "Family Safe",
        "desc": "Cisco FamilyShield blocks adult websites and phishing automatically.",
        "is_custom": False
    },
    {
        "id": "cleanbrowsing_family",
        "name": "CleanBrowsing Family Filter",
        "primary": "185.228.168.168",
        "secondary": "185.228.169.168",
        "category": "Family Safe",
        "desc": "Strict adult content filtering and Google SafeSearch enforcement.",
        "is_custom": False
    },
    {
        "id": "adguard_family",
        "name": "AdGuard Family Protection",
        "primary": "94.140.14.15",
        "secondary": "94.140.15.16",
        "category": "Family Safe",
        "desc": "Blocks adult websites, ads, and enables SafeSearch on search engines.",
        "is_custom": False
    }
]

TRANSLATIONS = {
    "en": {
        "app_title": "DNS SHIELD PRO",
        "app_subtitle": "Automated DNS Failover Sentinel • Multi-Provider Latency Benchmarking • Zero-Downtime Protection",
        "admin": "🛡️ ADMIN",
        "elevate_admin": "⚠️ ELEVATE TO ADMIN",
        "protected": "● PROTECTED",
        "paused": "● PAUSED",
        "active_protection": "Active Protection",
        "net_adapter": "🌐 NETWORK ADAPTER",
        "active_dns": "🎯 ACTIVE DNS RESOLVER",
        "live_latency": "⚡ LIVE LATENCY & HEALTH",
        "sentinel_metrics": "🛡️ SENTINEL METRICS",
        "auto_detect": "Auto-Detect (Primary)",
        "tab_live": "📊 Live Monitor & Graphs",
        "tab_benchmark": "🚀 DNS Benchmark & Server Hub",
        "tab_manual": "🔧 Adapter & Manual DNS",
        "tab_settings": "⚙️ Settings & Policies",
        "opt_fastest": "⚡ Optimize to Fastest DNS",
        "flush_dns": "🧹 Flush DNS Cache",
        "reset_dhcp": "🔄 Reset to DHCP",
        "copy_dns": "📋 Copy DNS Info",
        "clear_log": "Clear Log",
        "activity_log": "📋 REAL-TIME SENTINEL ACTIVITY LOG",
        "filter_all": "All",
        "filter_success": "Success",
        "filter_alerts": "Alerts",
        "filter_failover": "Failover",
        "filter_errors": "Errors",
        "search_placeholder": "🔍 Filter by name, IP, or keyword...",
        "add_custom_dns": "+ Add Custom DNS",
        "benchmark_all": "🚀 Benchmark All DNS",
        "benchmarking": "⏳ Benchmarking...",
        "cat_all": "All Providers",
        "cat_fast": "🚀 Ultra Fast",
        "cat_sec": "🛡️ Security",
        "cat_adblock": "🚫 Ad-Blocking",
        "cat_priv": "🔒 Privacy",
        "cat_family": "👨‍👩‍👦 Family Safe",
        "cat_custom": "⭐ Custom",
        "apply": "Apply",
        "test": "Test",
        "active_badge": "✓ ACTIVE CURRENT",
        "hardware_specs": "📡 NETWORK ADAPTER SPECIFICATIONS",
        "manual_dns_title": "✍️ CONFIGURE CUSTOM IPV4 DNS MANUALLY",
        "pri_dns_label": "Preferred DNS Server (Primary IPv4):",
        "sec_dns_label": "Alternate DNS Server (Secondary IPv4):",
        "apply_manual": "Apply Manual DNS",
        "diag_title": "🔍 INSTANT DOMAIN RESOLUTION TEST",
        "test_resolution": "Test Resolution",
        "net_tools_title": "🛠️ ADVANCED NETWORK DIAGNOSTIC & REPAIR",
        "repair_stack": "🔄 Repair Network Stack (Winsock/ARP)",
        "renew_ip": "🌐 Renew IP (DHCP Lease)",
        "switch_failover": "Enable Automatic Failover\nAutomatically switch to the fastest verified DNS when current server fails",
        "check_interval": "Health Check Interval\nFrequency of background DNS uptime probing (Seconds)",
        "fail_threshold": "Failover Threshold\nConsecutive unanswered queries before emergency failover is triggered",
        "win_autostart": "Launch with Windows\nStart DNS Shield Pro silently in the background at system startup",
        "min_tray": "Minimize to System Tray\nClosing the window sends the application to the notification area",
        "desktop_notify": "Desktop Notifications\nDisplay Windows notifications when automatic failover occurs",
        "test_domains": "Target Test Domains (Comma separated):",
        "save_domains": "Save Test Domains",
        "toast_flush": "✓ Windows DNS cache flushed instantly (0.1 ms)",
        "toast_dhcp": "✓ Network adapter reset to DHCP / ISP default",
        "toast_applied": "✓ DNS applied successfully:",
        "toast_repair": "✓ Network stack and ARP table purged successfully",
        "untested": "Untested",
        "latency_trend": "📈 LIVE LATENCY TREND (LAST 30 CHECKS)"
    }
}

DEFAULT_CONFIG = {
    "app_name": "DNS Shield Pro",
    "version": "2.5",
    "language": "en",
    "check_interval_seconds": 6,
    "fail_threshold": 2,
    "query_timeout_seconds": 1.5,
    "auto_switch_enabled": True,
    "selected_adapter": "Auto",
    "start_minimized": False,
    "minimize_to_tray": True,
    "auto_flush_cache": True,
    "notify_on_switch": True,
    "test_domains": ["google.com", "cloudflare.com", "one.one.one.one", "microsoft.com"],
    "dns_pool": DEFAULT_DNS_POOL
}


class ConfigManager:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self) -> dict:
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Merge with default ensuring all keys exist
                merged = DEFAULT_CONFIG.copy()
                for k, v in data.items():
                    if k == "dns_pool":
                        custom_entries = [item for item in v if item.get("is_custom", False)]
                        existing_ids = {item["id"] for item in DEFAULT_DNS_POOL}
                        for custom in custom_entries:
                            if custom.get("id") not in existing_ids:
                                DEFAULT_DNS_POOL.append(custom)
                        merged["dns_pool"] = DEFAULT_DNS_POOL
                    else:
                        merged[k] = v

                merged["language"] = "en"
                return merged
            except Exception as e:
                print(f"[Config] Error reading configuration file: {e}")

        config = DEFAULT_CONFIG.copy()
        self.save_config(config)
        return config

    def save_config(self, cfg: Optional[dict] = None) -> bool:
        if cfg is None:
            cfg = self.config
        try:
            temp_file = CONFIG_FILE + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            if os.path.exists(temp_file):
                os.replace(temp_file, CONFIG_FILE)
            return True
        except Exception as e:
            print(f"[Config] Error saving configuration file: {e}")
            return False

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value):
        self.config[key] = value
        self.save_config()

    def tr(self, key: str) -> str:
        """Retrieves English UI string."""
        translations = TRANSLATIONS.get("en", {})
        return translations.get(key, key)

    def add_custom_dns(self, name: str, primary: str, secondary: str = "", category: str = "Custom", desc: str = "") -> bool:
        """Adds a custom DNS server to the pool and persists it."""
        name = name.strip()
        primary = primary.strip()
        secondary = secondary.strip()

        if not name or not primary:
            return False

        custom_id = f"custom_{int(os.times().system * 1000)}"
        new_entry = {
            "id": custom_id,
            "name": name,
            "primary": primary,
            "secondary": secondary,
            "category": category or "Custom",
            "desc": desc or "User-defined custom DNS server.",
            "is_custom": True
        }

        pool = self.config.get("dns_pool", [])
        for item in pool:
            if item.get("primary") == primary and item.get("secondary") == secondary:
                item["name"] = name
                item["desc"] = desc
                self.save_config()
                return True

        pool.append(new_entry)
        self.set("dns_pool", pool)
        return True

    def remove_custom_dns(self, primary: str) -> bool:
        """Removes a custom DNS entry from the pool."""
        pool = self.config.get("dns_pool", [])
        initial_len = len(pool)
        pool = [item for item in pool if not (item.get("is_custom") and item.get("primary") == primary)]
        if len(pool) != initial_len:
            self.set("dns_pool", pool)
            return True
        return False

    @staticmethod
    def is_auto_start_enabled() -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, APP_REG_NAME)
                return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    @staticmethod
    def set_auto_start(enabled: bool) -> bool:
        """Sets or deletes Windows auto-start Run key in registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
                if enabled:
                    if getattr(sys, "frozen", False):
                        exe_path = sys.executable
                        cmd = f'"{exe_path}" --minimized'
                    else:
                        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
                        python_exe = sys.executable
                        pythonw_exe = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
                        exe_to_use = pythonw_exe if os.path.exists(pythonw_exe) else python_exe
                        cmd = f'"{exe_to_use}" "{script_path}" --minimized'

                    winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, cmd)
                else:
                    try:
                        winreg.DeleteValue(key, APP_REG_NAME)
                    except FileNotFoundError:
                        pass
            return True
        except Exception as e:
            print(f"[Config] Error modifying auto-start registry: {e}")
            return False
