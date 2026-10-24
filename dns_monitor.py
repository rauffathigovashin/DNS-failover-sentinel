import time
import threading
from concurrent.futures import ThreadPoolExecutor
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
        self.current_status_code = "ready"  # "ready", "ok", "warning", "switching", "error", "offline", "stopped"

        # Outage and Cooldown tracking
        self.was_offline = False
        self.last_failover_time = 0.0
        self.failover_cooldown = float(self.config_manager.get("failover_cooldown_seconds", 45))

        # History buffer for live sparkline graphing (last 30 points)
        self.latency_history: List[Dict] = []
        self.max_history_len = 30

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
        try:
            print(formatted)
        except Exception:
            pass

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.start_time = time.time()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="DNSMonitorWatchdog")
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

    def _record_latency(self, latency: float, status_code: str):
        self.latency_history.append({
            "time": time.time(),
            "latency": latency,
            "status": status_code
        })
        if len(self.latency_history) > self.max_history_len:
            self.latency_history.pop(0)

    def _notify_status(self):
        if self.on_status_change:
            data = {
                "adapter": self.current_adapter,
                "dns_list": self.current_dns_list,
                "latency_ms": self.current_latency,
                "status_text": self.current_status,
                "status_code": self.current_status_code,
                "fails": self.consecutive_fails,
                "threshold": self.config_manager.get("fail_threshold", 1),
                "auto_switch": self.config_manager.get("auto_switch_enabled", True),
                "total_checks": self.total_checks,
                "failovers": self.failover_count,
                "uptime": self.get_uptime_str(),
                "history": list(self.latency_history)
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
                primary_domain = test_domains[0] if test_domains else "google.com"
                secondary_domain = test_domains[1] if len(test_domains) > 1 else "cloudflare.com"
                timeout = max(1.5, float(self.config_manager.get("query_timeout_seconds", 2.0)))

                ok = False
                latency = 9999.0
                info = ""

                if self.current_dns_list:
                    pri_ip = self.current_dns_list[0]
                    has_sec = len(self.current_dns_list) > 1
                    sec_ip = self.current_dns_list[1] if has_sec else None

                    # 1. Test primary and secondary DNS in parallel on primary_domain
                    with ThreadPoolExecutor(max_workers=2) as _ex:
                        f_pri = _ex.submit(DNSCore.test_dns_server, pri_ip, primary_domain, timeout)
                        f_sec = _ex.submit(DNSCore.test_dns_server, sec_ip, primary_domain, timeout) if has_sec else None
                        ok_pri, lat_pri, info_pri = f_pri.result()
                        ok_sec, lat_sec, info_sec = (f_sec.result() if f_sec else (False, 9999.0, ""))

                    if ok_pri:
                        ok, latency, info = True, lat_pri, info_pri
                    elif ok_sec:
                        ok, latency, info = True, lat_sec, f"Secondary DNS ({sec_ip})"
                    else:
                        # 2. Both failed on primary domain — ALWAYS test secondary fallback domain in parallel!
                        with ThreadPoolExecutor(max_workers=2) as _ex2:
                            f2_pri = _ex2.submit(DNSCore.test_dns_server, pri_ip, secondary_domain, timeout)
                            f2_sec = _ex2.submit(DNSCore.test_dns_server, sec_ip, secondary_domain, timeout) if has_sec else None
                            ok2_pri, lat2_pri, info2_pri = f2_pri.result()
                            ok2_sec, lat2_sec, info2_sec = (f2_sec.result() if f2_sec else (False, 9999.0, ""))

                        if ok2_pri:
                            ok, latency, info = True, lat2_pri, f"Fallback Domain ({secondary_domain})"
                        elif ok2_sec:
                            ok, latency, info = True, lat2_sec, f"Secondary Fallback ({secondary_domain})"
                        else:
                            # 3. Quick confirmation check (300ms pause) to eliminate transient Wi-Fi jitter
                            time.sleep(0.3)
                            ok_retry, lat_retry, info_retry = DNSCore.test_dns_server(pri_ip, primary_domain, timeout=1.2)
                            if ok_retry:
                                ok, latency, info = True, lat_retry, "Transient Recovered"
                            else:
                                ok, latency, info = False, 9999.0, info_pri

                else:
                    ok, latency, info = DNSCore.test_current_dns_health(test_domains=test_domains, timeout=timeout)

                if ok:
                    if self.was_offline:
                        self.was_offline = False
                        self.log("Internet link and DNS resolution restored. Active protection operational.", "success")

                    self.consecutive_fails = 0
                    self.current_latency = latency
                    self.current_status = f"Protected & Healthy ({latency} ms)"
                    self.current_status_code = "ok"
                    self._record_latency(latency, "ok")
                    self._notify_status()
                else:
                    # DNS failed. Check if Internet (Layer 3/4) is actually online or offline!
                    is_online = DNSCore.is_network_online(timeout=1.5)
                    if not is_online:
                        # INTERNET OUTAGE DETECTED! (Router, Cable, Wi-Fi, or ISP down)
                        # CRITICAL: DO NOT trigger failover, DO NOT reset adapter!
                        if not self.was_offline:
                            self.was_offline = True
                            self.log("⚠️ Internet connection down (ISP / Gateway link lost). Preserving DNS settings.", "warning")

                        self.current_latency = 9999.0
                        self.current_status = "Internet Disconnected (Waiting for connection)"
                        self.current_status_code = "offline"
                        self._record_latency(0.0, "offline")
                        self._notify_status()

                        if self.stop_event.wait(timeout=5):
                            break
                        continue
                    else:
                        # INTERNET IS CONFIRMED UP, BUT DNS IS FAILING!
                        self.was_offline = False
                        self.consecutive_fails += 1
                        fail_threshold = max(2, int(self.config_manager.get("fail_threshold", 2)))
                        self.current_latency = 9999.0
                        dns_display = ", ".join(self.current_dns_list) or "DHCP Default"

                        # Require consecutive fails to reach threshold! NEVER failover on 1 single dropped packet!
                        if self.consecutive_fails >= fail_threshold:
                            self.current_status = "DNS Failure! Switching to fastest verified server..."
                            self.current_status_code = "warning"
                            self._record_latency(9999.0, "warning")
                            self._notify_status()

                            self.log(
                                f"Active DNS [{dns_display}] confirmed down ({self.consecutive_fails}/{fail_threshold} checks failed). Triggering emergency failover...",
                                "failover"
                            )

                            if self.config_manager.get("auto_switch_enabled", True):
                                self._trigger_auto_failover()
                            else:
                                self.current_status = "DNS Down (Auto-Failover Disabled)"
                                self.current_status_code = "error"
                                self._notify_status()
                                self.log("DNS failure detected, but automatic failover is disabled in settings.", "error")
                        else:
                            self.current_status = f"DNS Warning ({self.consecutive_fails}/{fail_threshold})"
                            self.current_status_code = "warning"
                            self._record_latency(9999.0, "warning")
                            self._notify_status()
                            self.log(
                                f"Active DNS [{dns_display}] did not respond [{info}] (Check {self.consecutive_fails}/{fail_threshold}). Re-verifying on next cycle...",
                                "warning"
                            )

            except Exception as e:
                self.log(f"Watchdog monitoring loop error: {e}", "error")

            interval = max(4, self.config_manager.get("check_interval_seconds", 8))
            if self.stop_event.wait(timeout=interval):
                break

    def _trigger_auto_failover(self):
        """
        Ultra-Fast Emergency Failover (< 300ms):
        Races top resilient Anycast resolvers in parallel with sub-second race probe.
        Applies verified fastest primary and a distinct healthy secondary.
        If all fail, resets to DHCP so the user is never left without internet!
        """
        now = time.time()
        cooldown = max(20.0, float(self.config_manager.get("failover_cooldown_seconds", 30)))
        if (now - self.last_failover_time) < cooldown:
            remaining = int(cooldown - (now - self.last_failover_time))
            self.log(f"Failover cooldown active ({remaining}s remaining). Suppressing switch to avoid adapter thrashing.", "info")
            return

        self.last_failover_time = now
        self.current_status = "DNS Failure! Selecting fastest verified server..."
        self.current_status_code = "switching"
        self._notify_status()
        self.log("CRITICAL: Active DNS unreachable while internet is up! Initiating ultra-fast failover...", "failover")

        pool = self.config_manager.get("dns_pool", [])
        current_ips = set(self.current_dns_list)

        # Exclude currently dead IPs, known-blocked 1.1.1.1, and restrictive Family/Adblock categories from emergency pool
        priority_candidates = []
        fallback_candidates = []

        for item in pool:
            pri = item.get("primary", "")
            # Skip if primary is in current failing IPs or known-blocked 1.1.1.1
            if pri in current_ips or pri == "1.1.1.1":
                continue

            category = item.get("category", "")
            # Prioritize Ultra Fast, General, Privacy (unfiltered)
            if category in ("Ultra Fast", "Privacy", "General", "Custom"):
                priority_candidates.append(item)
            else:
                fallback_candidates.append(item)

        candidates = (priority_candidates[:6] if priority_candidates else fallback_candidates[:6])
        if not candidates:
            candidates = pool[:6]

        # Fast parallel race probe (< 150ms)
        alive_servers = DNSCore.fast_failover_probe(candidates, domain="google.com", timeout=0.85)

        if not alive_servers:
            # Broader quick sweep across pool
            alive_servers = DNSCore.fast_failover_probe(pool, domain="google.com", timeout=1.0)

        if not alive_servers:
            # SAFETY FALLBACK: Reset to DHCP so user's internet is never broken!
            self.current_status = "Resetting to DHCP (No custom DNS reachable)"
            self.current_status_code = "warning"
            self._notify_status()
            self.log("SAFETY FALLBACK: No alternative DNS responded. Resetting adapter to Automatic (DHCP) to restore internet access.", "warning")
            ok_dhcp, _ = DNSCore.reset_adapter_dns_to_dhcp(self.current_adapter)
            if ok_dhcp:
                self.current_dns_list = []
                self.consecutive_fails = 0
                self.current_status = "Active: DHCP (Automatic / ISP Default)"
                self.current_status_code = "ok"
                self._notify_status()
                return

            self.current_status = "Critical: No DNS reachable"
            self.current_status_code = "error"
            self._notify_status()
            self.log("FAILOVER NOTICE: None of the alternative DNS servers responded.", "error")
            self.consecutive_fails = 1
            return

        best = alive_servers[0]
        best_name = best["name"]
        best_primary = best["primary"] if best.get("primary_ok") else best["secondary"]

        # Ensure secondary is distinct and healthy
        best_secondary = ""
        if best.get("secondary") and best.get("secondary_ok") and best["secondary"] != best_primary:
            best_secondary = best["secondary"]
        elif len(alive_servers) > 1:
            second_best = alive_servers[1]
            sec_candidate = second_best["primary"] if second_best.get("primary_ok") else second_best.get("secondary", "")
            if sec_candidate and sec_candidate != best_primary:
                best_secondary = sec_candidate

        self.log(f"Applying verified DNS: {best_name} [{best_primary}] ({best['latency_ms']} ms)...", "info")

        success, msg = DNSCore.set_adapter_dns(self.current_adapter, best_primary, best_secondary)
        if success:
            self.consecutive_fails = 0
            self.failover_count += 1
            self.current_latency = best["latency_ms"]
            self.current_dns_list = [best_primary] + ([best_secondary] if best_secondary else [])
            self.current_status = f"Recovered: {best_name} ({self.current_latency} ms)"
            self.current_status_code = "ok"
            self._record_latency(self.current_latency, "ok")
            self._notify_status()

            self.log(f"FAILOVER SUCCESS: Internet restored via {best_name} [{best_primary}] ({self.current_latency} ms)!", "success")

            if self.on_dns_switched:
                try:
                    self.on_dns_switched(best_name, best_primary, self.current_latency)
                except Exception:
                    pass
        else:
            self.current_status = "Failover Error (Permission Denied)"
            self.current_status_code = "error"
            self._notify_status()
            self.log("Failed to apply new DNS. Please run DNS Shield Pro as Administrator!", "error")

    def force_quick_optimize(self, progress_callback: Optional[Callable[[int, int, Dict], None]] = None) -> Dict:
        """
        1-Click Instant Optimization:
        Verifies internet first, benchmarks all DNS servers with controlled concurrency and sets the fastest.
        """
        if not DNSCore.is_network_online(timeout=1.5):
            self.log("Cannot optimize DNS: Internet connection is currently offline! Check your cable/Wi-Fi router.", "warning")
            return {"success": False, "error": "Internet connection is offline", "benchmarks": []}

        self.log("Manual DNS optimization triggered. Running latency benchmark...", "info")
        pool = self.config_manager.get("dns_pool", [])
        benchmarks = DNSCore.benchmark_all_servers(pool, timeout=1.8, progress_callback=progress_callback)
        alive = [s for s in benchmarks if s.get("is_alive")]

        if alive:
            best = alive[0]
            best_primary = best["primary"] if best.get("primary_ok") else best["secondary"]
            best_secondary = ""
            if best.get("secondary") and best.get("secondary_ok") and best["secondary"] != best_primary:
                best_secondary = best["secondary"]
            elif len(alive) > 1:
                second_best = alive[1]
                sec_cand = second_best["primary"] if second_best.get("primary_ok") else second_best.get("secondary", "")
                if sec_cand and sec_cand != best_primary:
                    best_secondary = sec_cand

            adapter = self.get_selected_adapter()

            ok, msg = DNSCore.set_adapter_dns(adapter, best_primary, best_secondary)
            if ok:
                time.sleep(0.1)
                self.consecutive_fails = 0
                self.current_dns_list = [best_primary] + ([best_secondary] if best_secondary else [])
                self.current_latency = best["latency_ms"]
                self.current_status = f"Optimized: {best['name']} ({best['latency_ms']} ms)"
                self.current_status_code = "ok"
                self._record_latency(best["latency_ms"], "ok")
                self._notify_status()
                self.log(f"Optimization complete! Configured {best['name']} ({best['latency_ms']} ms) on {adapter}.", "success")
                return {"success": True, "best": best, "benchmarks": benchmarks}
            else:
                self.log(f"Could not apply DNS settings: {msg}", "error")
                return {"success": False, "error": msg, "benchmarks": benchmarks}
        else:
            self.log("No responsive DNS servers detected during benchmark!", "error")
            return {"success": False, "error": "No reachable DNS servers found", "benchmarks": benchmarks}
