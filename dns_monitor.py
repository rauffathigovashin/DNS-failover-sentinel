import time
import threading
from typing import Callable, Optional, Dict, List
from dns_core import DNSCore
from config_manager import ConfigManager

class DNSMonitor:
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.running = False
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

        # Statistics & State
        self.start_time: Optional[float] = None
        self.total_checks = 0
        self.failover_count = 0
        self.consecutive_fails = 0

        self.current_adapter = "Ethernet"
        self.current_dns_list: List[str] = []
        self.current_latency = 0.0
        self.current_status = "Ready"
        self.current_status_code = "ready"  # "ready", "ok", "warning", "switching", "error", "stopped"

        # GUI Callbacks
        self.on_status_change: Optional[Callable[[Dict], None]] = None
        self.on_log_message: Optional[Callable[[str, str], None]] = None  # (message, level)
        self.on_dns_switched: Optional[Callable[[str, str, float], None]] = None  # (name, ip, latency)

    def log(self, message: str, level: str = "info"):
        timestamp = time.strftime("%H:%M:%S")
        tag_map = {
            "success": "[SUCCESS]",
            "warning": "[WARNING]",
            "error": "[ERROR]",
            "failover": "[FAILOVER]",
            "info": "[INFO]"
        }
        tag = tag_map.get(level, "[INFO]")
        formatted = f"[{timestamp}] {tag} {message}"
        if self.on_log_message:
            try:
                self.on_log_message(formatted, level)
            except Exception:
                pass
        print(formatted)

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.log("DNS Shield Protection Engine active. Continuous background monitoring started.", "success")

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.current_status = "Monitoring Paused"
        self.current_status_code = "stopped"
        self._notify_status()
        self.log("DNS Shield Protection Engine paused.", "warning")

    def get_uptime_str(self) -> str:
        if not self.start_time or not self.running:
            return "00:00:00"
        elapsed = int(time.time() - self.start_time)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _notify_status(self):
        if self.on_status_change:
            data = {
                "adapter": self.current_adapter,
                "dns_list": self.current_dns_list,
                "latency_ms": self.current_latency,
                "status_text": self.current_status,
                "status_code": self.current_status_code,
                "fails": self.consecutive_fails,
                "threshold": self.config_manager.get("fail_threshold", 2),
                "auto_switch": self.config_manager.get("auto_switch_enabled", True),
                "total_checks": self.total_checks,
                "failovers": self.failover_count,
                "uptime": self.get_uptime_str()
            }
            try:
                self.on_status_change(data)
            except Exception:
                pass

    def get_selected_adapter(self) -> str:
        saved = self.config_manager.get("selected_adapter", "Auto")
        if saved == "Auto" or not saved:
            primary = DNSCore.get_primary_active_adapter()
            return primary or "Ethernet"
        return saved

    def _monitor_loop(self):
        while self.running and not self.stop_event.is_set():
            try:
                self.total_checks += 1
                self.current_adapter = self.get_selected_adapter()
                self.current_dns_list = DNSCore.get_adapter_dns(self.current_adapter)

                test_domains = self.config_manager.get("test_domains", ["google.com", "cloudflare.com", "one.one.one.one"])
                timeout = self.config_manager.get("query_timeout_seconds", 1.5)

                if self.current_dns_list:
                    # Test primary DNS server configured on adapter
                    primary_dns = self.current_dns_list[0]
                    ok, latency, info = DNSCore.test_dns_server(primary_dns, domain=test_domains[0], timeout=timeout)
                else:
                    # Test via system resolver (DHCP)
                    ok, latency, info = DNSCore.test_current_dns_health(test_domains=test_domains, timeout=timeout)

                if ok:
                    self.consecutive_fails = 0
                    self.current_latency = latency
                    self.current_status = f"Protected & Healthy ({latency} ms)"
                    self.current_status_code = "ok"
                    self._notify_status()
                else:
                    self.consecutive_fails += 1
                    fail_threshold = self.config_manager.get("fail_threshold", 2)
                    self.current_latency = 9999.0
                    self.current_status = f"DNS Unresponsive ({self.consecutive_fails}/{fail_threshold})"
                    self.current_status_code = "warning"
                    self._notify_status()

                    dns_display = ", ".join(self.current_dns_list) or "DHCP Default"
                    self.log(
                        f"Active DNS [{dns_display}] did not respond! [Error: {info}] (Attempt {self.consecutive_fails}/{fail_threshold})",
                        "warning"
                    )

                    if self.consecutive_fails >= fail_threshold:
                        if self.config_manager.get("auto_switch_enabled", True):
                            self._trigger_auto_failover()
                        else:
                            self.current_status = "DNS Down (Auto-Failover Disabled)"
                            self.current_status_code = "error"
                            self._notify_status()
                            self.log("DNS failure detected, but automatic failover is disabled in settings.", "error")

            except Exception as e:
                self.log(f"Watchdog monitoring loop error: {e}", "error")

            # Wait for configured check interval
            interval = max(3, self.config_manager.get("check_interval_seconds", 6))
            if self.stop_event.wait(timeout=interval):
                break

    def _trigger_auto_failover(self):
        """
        Triggered when consecutive DNS timeouts reach threshold.
        Benchmarks candidate pool, verifies resolution, and switches to best candidate.
        """
        self.current_status = "DNS Failure! Selecting fastest healthy server..."
        self.current_status_code = "switching"
        self._notify_status()
        self.log("CRITICAL: Active DNS unreachable! Initiating emergency auto-failover...", "failover")

        pool = self.config_manager.get("dns_pool", [])
        benchmarks = DNSCore.benchmark_all_servers(pool, timeout=1.5)
        alive_servers = [s for s in benchmarks if s["is_alive"]]

        if not alive_servers:
            self.current_status = "Critical: No alternative DNS servers reachable!"
            self.current_status_code = "error"
            self._notify_status()
            self.log("CRITICAL ERROR: None of the alternative DNS servers responded. Check network cable/router!", "error")
            self.consecutive_fails = 0
            return

        # Attempt to apply the best responding server
        applied_successfully = False
        for candidate in alive_servers[:3]:  # Try top 3 responsive servers
            best_name = candidate["name"]
            best_primary = candidate["primary"] if candidate["primary_ok"] else candidate["secondary"]
            best_secondary = candidate["secondary"] if (candidate["secondary"] and candidate["secondary_ok"]) else (candidate["primary"] if candidate["primary_ok"] else "")

            self.log(f"Testing & applying fastest candidate: {best_name} ({best_primary} - {candidate['latency_ms']} ms)...", "info")

            success, msg = DNSCore.set_adapter_dns(self.current_adapter, best_primary, best_secondary)
            if success:
                # Verify resolution
                test_ok, test_ms, _ = DNSCore.test_dns_server(best_primary, domain="google.com", timeout=1.5)
                if test_ok:
                    self.consecutive_fails = 0
                    self.failover_count += 1
                    self.current_latency = test_ms
                    self.current_dns_list = [best_primary] + ([best_secondary] if best_secondary else [])
                    self.current_status = f"Recovered: {best_name} ({test_ms} ms)"
                    self.current_status_code = "ok"
                    self._notify_status()

                    self.log(f"FAILOVER SUCCESS: Internet restored via {best_name} [{best_primary}] ({test_ms} ms)", "success")

                    if self.on_dns_switched:
                        try:
                            self.on_dns_switched(best_name, best_primary, test_ms)
                        except Exception:
                            pass
                    applied_successfully = True
                    break

        if not applied_successfully:
            self.current_status = "Failover Error (Permission Denied)"
            self.current_status_code = "error"
            self._notify_status()
            self.log("Failed to apply new DNS. Please ensure DNS Shield Pro is running as Administrator!", "error")

    def force_quick_optimize(self) -> Dict:
        """
        Manual 1-click optimization to benchmark all DNS servers and switch to the lowest latency one.
        """
        self.log("Manual DNS optimization triggered. Running parallel latency benchmark...", "info")
        pool = self.config_manager.get("dns_pool", [])
        benchmarks = DNSCore.benchmark_all_servers(pool, timeout=1.5)
        alive = [s for s in benchmarks if s["is_alive"]]

        if alive:
            best = alive[0]
            best_primary = best["primary"] if best["primary_ok"] else best["secondary"]
            best_secondary = best["secondary"] if (best["secondary"] and best["secondary_ok"]) else ""
            adapter = self.get_selected_adapter()

            ok, msg = DNSCore.set_adapter_dns(adapter, best_primary, best_secondary)
            if ok:
                self.consecutive_fails = 0
                self.current_dns_list = [best_primary] + ([best_secondary] if best_secondary else [])
                self.current_latency = best["latency_ms"]
                self.current_status = f"Optimized: {best['name']} ({best['latency_ms']} ms)"
                self.current_status_code = "ok"
                self._notify_status()
                self.log(f"Optimization complete! Configured {best['name']} ({best['latency_ms']} ms) on {adapter}.", "success")
                return {"success": True, "best": best, "benchmarks": benchmarks}
            else:
                self.log(f"Could not apply DNS settings: {msg}", "error")
                return {"success": False, "error": msg, "benchmarks": benchmarks}
        else:
            self.log("No responsive DNS servers detected during benchmark!", "error")
            return {"success": False, "error": "No reachable DNS servers found", "benchmarks": benchmarks}
