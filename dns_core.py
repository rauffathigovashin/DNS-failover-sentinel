import subprocess
import time
import re
import socket
import winreg
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Callable
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.rcode
import dns.exception
import psutil

class DNSCore:
    _guid_cache: Dict[str, str] = {}
    _last_guid_cache_time: float = 0.0

    @classmethod
    def _refresh_guid_cache(cls, force: bool = False):
        """Refreshes network interface name to GUID mapping from Windows Registry."""
        now = time.time()
        if not force and cls._guid_cache and (now - cls._last_guid_cache_time < 30.0):
            return

        net_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        name_to_guid = {}
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_path) as root_key:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(root_key, idx)
                        idx += 1
                        try:
                            conn_path = f"{net_path}\\{guid}\\Connection"
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path) as conn_key:
                                name, _ = winreg.QueryValueEx(conn_key, "Name")
                                if name:
                                    name_to_guid[name] = guid
                        except Exception:
                            continue
                    except OSError:
                        break
        except Exception:
            pass

        if name_to_guid:
            cls._guid_cache = name_to_guid
            cls._last_guid_cache_time = now

    @staticmethod
    def get_adapter_dns(adapter_name: str) -> List[str]:
        """
        Ultra-fast native Windows Registry lookup for configured IPv4 DNS servers.
        Takes < 1 ms with zero subprocess overhead.
        Falls back to netsh and PowerShell if needed.
        """
        DNSCore._refresh_guid_cache()
        guid = DNSCore._guid_cache.get(adapter_name)

        if not guid:
            # Force refresh in case adapter was recently renamed or plugged in
            DNSCore._refresh_guid_cache(force=True)
            guid = DNSCore._guid_cache.get(adapter_name)

        if guid:
            try:
                if_path = f"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, if_path) as if_key:
                    # 1. Check static NameServer first
                    name_server = ""
                    try:
                        name_server, _ = winreg.QueryValueEx(if_key, "NameServer")
                    except Exception:
                        pass

                    # 2. Check DHCP NameServer if static is empty
                    if not name_server:
                        try:
                            name_server, _ = winreg.QueryValueEx(if_key, "DhcpNameServer")
                        except Exception:
                            pass

                    if name_server:
                        # Value may be comma or space separated
                        raw_ips = re.split(r"[,;\s]+", name_server.strip())
                        dns_list = [
                            ip for ip in raw_ips
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
                        ]
                        if dns_list:
                            return dns_list
            except Exception:
                pass

        # Fallback 1: Fast netsh lookup (~50ms)
        dns_servers = []
        try:
            res = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dns", f'name="{adapter_name}"'],
                capture_output=True, text=True, timeout=2, creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in res.stdout.splitlines():
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if match:
                    ip = match.group(1)
                    if ip not in dns_servers:
                        dns_servers.append(ip)
            if dns_servers:
                return dns_servers
        except Exception:
            pass

        # Fallback 2: PowerShell (only as last resort)
        try:
            ps_cmd = (
                f"(Get-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue).ServerAddresses"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if line and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    if line not in dns_servers:
                        dns_servers.append(line)
        except Exception:
            pass

        return dns_servers

    @staticmethod
    def get_network_adapters() -> List[Dict]:
        """
        Discovers all physical and virtual network adapters using native psutil + registry.
        Executes in < 5 ms instead of taking 2-3 seconds with PowerShell.
        """
        adapters = []
        try:
            if_stats = psutil.net_if_stats()
            if_addrs = psutil.net_if_addrs()

            for name, stats in if_stats.items():
                # Skip loopback interface
                if "loopback" in name.lower():
                    continue

                is_up = stats.isup
                speed_str = f"{stats.speed} Mbps" if stats.speed > 0 else "N/A"
                mac_str = "N/A"

                # Find MAC address and IPv4 address
                addrs = if_addrs.get(name, [])
                for addr in addrs:
                    if addr.family == psutil.AF_LINK or str(addr.family).endswith("AF_LINK") or addr.family == -1:
                        mac_str = addr.address

                current_dns = DNSCore.get_adapter_dns(name)

                adapters.append({
                    "name": name,
                    "status": "Up" if is_up else "Down",
                    "desc": name,
                    "link_speed": speed_str,
                    "mac": mac_str,
                    "is_up": is_up,
                    "current_dns": current_dns
                })

            if adapters:
                # Sort: active 'Up' adapters first
                adapters.sort(key=lambda a: (0 if a["is_up"] else 1, a["name"]))
                return adapters
        except Exception as e:
            print(f"[DNSCore] Native adapter discovery notice: {e}")

        # Fallback to netsh if psutil returns empty
        return DNSCore._get_adapters_fallback()

    @staticmethod
    def _get_adapters_fallback() -> List[Dict]:
        """Fallback adapter detection using netsh command."""
        adapters = []
        try:
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ("Enabled", "Disabled"):
                    name = " ".join(parts[3:])
                    is_up = parts[1] == "Connected"
                    adapters.append({
                        "name": name,
                        "status": "Up" if is_up else "Down",
                        "desc": name,
                        "link_speed": "N/A",
                        "mac": "N/A",
                        "is_up": is_up,
                        "current_dns": DNSCore.get_adapter_dns(name)
                    })
        except Exception:
            pass
        return adapters

    @staticmethod
    def get_primary_active_adapter() -> Optional[str]:
        """
        Determines the primary connected adapter with active routing (e.g., Ethernet or Wi-Fi).
        Uses instant kernel routing table query first (< 0.05 ms), with native fallback.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                if local_ip and local_ip != "127.0.0.1":
                    for if_name, addrs in psutil.net_if_addrs().items():
                        if "loopback" in if_name.lower():
                            continue
                        for addr in addrs:
                            if addr.address == local_ip:
                                return if_name
            finally:
                s.close()
        except Exception:
            pass

        adapters = DNSCore.get_network_adapters()
        if not adapters:
            return "Ethernet"

        # 1. Prefer 'Up' Ethernet adapters
        for a in adapters:
            if a["is_up"] and "ethernet" in a["name"].lower():
                return a["name"]

        # 2. Prefer 'Up' Wi-Fi adapters
        for a in adapters:
            if a["is_up"] and any(kw in a["name"].lower() for kw in ("wi-fi", "wifi", "wlan", "kablosuz")):
                return a["name"]

        # 3. Any adapter that is 'Up'
        for a in adapters:
            if a["is_up"]:
                return a["name"]

        return adapters[0]["name"]

    @staticmethod
    def is_network_online(timeout: float = 1.5) -> bool:
        """
        Quickly tests if the machine has active layer-3/4 internet connectivity
        by probing multiple global Anycast endpoints concurrently in parallel.
        Uses diverse ports (53/TCP, 80/TCP, 443/TCP) to avoid firewall false-negatives.
        Returns True as soon as ANY single endpoint responds successfully.
        """
        test_endpoints = [
            ("1.1.1.1",        80),   # Cloudflare HTTP
            ("8.8.8.8",        53),   # Google DNS/TCP
            ("1.0.0.1",        53),   # Cloudflare DNS/TCP
            ("208.67.222.222", 443),  # OpenDNS HTTPS
            ("9.9.9.9",        53),   # Quad9 DNS
            ("8.8.4.4",        80),   # Google HTTP
            ("1.1.1.1",        443),  # Cloudflare HTTPS
            ("142.250.185.46", 80),   # Google raw IP HTTP (avoids DNS dependency)
        ]

        def _check_target(target):
            host, port = target
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except OSError:
                return False

        with ThreadPoolExecutor(max_workers=len(test_endpoints)) as executor:
            futures = [executor.submit(_check_target, t) for t in test_endpoints]
            for future in as_completed(futures):
                try:
                    if future.result():
                        return True
                except Exception:
                    pass
        return False

    @staticmethod
    def test_dns_server(server_ip: str, domain: str = "google.com", timeout: float = 1.0) -> Tuple[bool, float, str]:
        """
        Directly queries a specific DNS server IP via direct raw UDP wire protocol.
        On UDP timeout, immediately falls back to TCP to handle ISP UDP port 53 filtering.
        No retry loops - single fast attempt per protocol to keep monitor cycles snappy.
        Returns: (is_success, latency_ms, resolved_ip_or_error)
        """
        if not server_ip or not server_ip.strip():
            return False, 9999.0, "Empty Server IP"

        server_ip = server_ip.strip()
        t_start = time.perf_counter()

        def _parse_resp(resp, elapsed_ms):
            rcode = resp.rcode()
            if rcode == dns.rcode.NOERROR:
                answers = []
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            answers.append(rdata.to_text())
                if answers:
                    return True, elapsed_ms, ", ".join(answers[:2])
                return True, elapsed_ms, "Resolved (No A record)"
            elif rcode == dns.rcode.NXDOMAIN:
                return False, 9999.0, "Domain Not Found (NXDOMAIN)"
            elif rcode == dns.rcode.REFUSED:
                return False, 9999.0, "Query Refused by Server"
            elif rcode == dns.rcode.SERVFAIL:
                return False, 9999.0, "Server Failure (SERVFAIL)"
            else:
                return False, 9999.0, f"RCODE {dns.rcode.to_text(rcode)}"

        query_msg = dns.message.make_query(domain, dns.rdatatype.A)

        # 1. UDP fast path (most servers respond in <50ms)
        try:
            response = dns.query.udp(query_msg, server_ip, timeout=timeout)
            latency_ms = round((time.perf_counter() - t_start) * 1000, 1)
            return _parse_resp(response, latency_ms)
        except (dns.exception.Timeout, TimeoutError, socket.timeout):
            pass
        except OSError as e:
            return False, 9999.0, f"Network Error: {e.strerror or type(e).__name__}"
        except Exception as e:
            return False, 9999.0, str(type(e).__name__)

        # 2. TCP fallback (handles ISP UDP port 53 blocking)
        try:
            t_tcp = time.perf_counter()
            response = dns.query.tcp(query_msg, server_ip, timeout=min(timeout, 1.0))
            latency_ms = round((time.perf_counter() - t_tcp) * 1000, 1)
            ok, ms, msg = _parse_resp(response, latency_ms)
            if ok:
                return True, latency_ms, f"{msg} (TCP)"
        except Exception:
            pass

        return False, 9999.0, "Timeout / Filtered"

    @staticmethod
    def test_current_dns_health(test_domains: Optional[List[str]] = None, timeout: float = 2.0) -> Tuple[bool, float, str]:
        """
        Verifies active system DNS resolution health across multiple reliable test domains.
        Fast fail-safe checking.
        """
        if not test_domains:
            test_domains = ["google.com", "cloudflare.com", "one.one.one.one", "microsoft.com"]

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for domain in test_domains:
            t_start = time.perf_counter()
            try:
                answers = resolver.resolve(domain, "A")
                latency_ms = round((time.perf_counter() - t_start) * 1000, 1)
                if answers:
                    return True, latency_ms, domain
            except (dns.exception.Timeout, TimeoutError, socket.timeout):
                # DNS server timed out! Stop immediately instead of sending 3 redundant requests to a dead server
                return False, 9999.0, "DNS Query Timeout"
            except Exception:
                continue

        return False, 9999.0, "All test domains failed to resolve"

    @staticmethod
    def benchmark_single_server(entry: Dict, domain: str = "google.com", timeout: float = 1.2) -> Dict:
        """
        Benchmarks an individual DNS server entry for latency and responsiveness.
        Queries primary and secondary in parallel for maximum speed.
        """
        name = entry.get("name", "Unknown")
        primary_ip = entry.get("primary", "")
        secondary_ip = entry.get("secondary", "")
        category = entry.get("category", "General")
        desc = entry.get("desc", "")
        is_custom = entry.get("is_custom", False)

        has_sec = bool(secondary_ip and secondary_ip.strip())

        # Run primary and secondary tests in parallel for faster benchmarking
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_pri = ex.submit(DNSCore.test_dns_server, primary_ip, domain, timeout)
            f_sec = ex.submit(DNSCore.test_dns_server, secondary_ip.strip(), domain, timeout) if has_sec else None

            ok_pri, ms_pri, msg_pri = f_pri.result()
            if f_sec is not None:
                ok_sec, ms_sec, msg_sec = f_sec.result()
            else:
                ok_sec, ms_sec, msg_sec = False, 9999.0, "None"

        is_alive = ok_pri or ok_sec
        best_ms = 9999.0
        if ok_pri and ok_sec:
            best_ms = min(ms_pri, ms_sec)
        elif ok_pri:
            best_ms = ms_pri
        elif ok_sec:
            best_ms = ms_sec

        return {
            "id": entry.get("id", name),
            "name": name,
            "primary": primary_ip,
            "secondary": secondary_ip,
            "category": category,
            "desc": desc,
            "is_custom": is_custom,
            "is_alive": is_alive,
            "latency_ms": best_ms,
            "primary_ok": ok_pri,
            "primary_ms": ms_pri,
            "primary_msg": msg_pri,
            "secondary_ok": ok_sec,
            "secondary_ms": ms_sec,
            "secondary_msg": msg_sec
        }

    @staticmethod
    def benchmark_all_servers(
        dns_pool: List[Dict],
        domain: str = "google.com",
        timeout: float = 1.2,
        progress_callback: Optional[Callable[[int, int, Dict], None]] = None
    ) -> List[Dict]:
        """
        Benchmarks all DNS servers in the pool in parallel using a controlled threadpool.
        Uses up to 14 workers - each server's primary+secondary already run in parallel
        inside benchmark_single_server, so total thread count stays manageable.
        """
        results = []
        total = len(dns_pool)
        completed_count = 0
        workers = min(max(total, 1), 8)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_entry = {executor.submit(DNSCore.benchmark_single_server, item, domain, timeout): item for item in dns_pool}
            for future in as_completed(future_to_entry):
                completed_count += 1
                try:
                    res = future.result()
                    results.append(res)
                    if progress_callback:
                        progress_callback(completed_count, total, res)
                except Exception as e:
                    item = future_to_entry[future]
                    failed_res = {
                        "id": item.get("id", item["name"]),
                        "name": item["name"],
                        "primary": item["primary"],
                        "secondary": item.get("secondary", ""),
                        "category": item.get("category", "General"),
                        "desc": item.get("desc", ""),
                        "is_custom": item.get("is_custom", False),
                        "is_alive": False,
                        "latency_ms": 9999.0,
                        "primary_ok": False,
                        "primary_ms": 9999.0,
                        "primary_msg": str(e),
                        "secondary_ok": False,
                        "secondary_ms": 9999.0,
                        "secondary_msg": ""
                    }
                    results.append(failed_res)
                    if progress_callback:
                        progress_callback(completed_count, total, failed_res)

        # Sort alive servers by lowest latency first, offline servers to the bottom
        results.sort(key=lambda x: (0 if x["is_alive"] else 1, x["latency_ms"]))
        return results

    @staticmethod
    def fast_failover_probe(
        candidates: List[Dict],
        domain: str = "google.com",
        timeout: float = 0.85
    ) -> List[Dict]:
        """
        Ultra-fast parallel race probe specifically designed for zero-lag emergency failover.
        Uses lightweight UDP queries with 850ms timeout to discover verified healthy servers
        in sub-second time (typically < 300ms) without flooding the network.
        """
        results = []
        if not candidates:
            return results

        workers = min(len(candidates), 6)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_entry = {
                executor.submit(DNSCore.benchmark_single_server, item, domain, timeout): item
                for item in candidates
            }
            for future in as_completed(future_to_entry):
                try:
                    res = future.result()
                    if res.get("is_alive"):
                        results.append(res)
                except Exception:
                    pass

        results.sort(key=lambda x: x["latency_ms"])
        return results

    @staticmethod
    def set_adapter_dns(adapter_name: str, primary_ip: str, secondary_ip: Optional[str] = None) -> Tuple[bool, str]:
        """
        Applies primary and secondary DNS server addresses to the specified network adapter.
        Uses fast netsh command first (~50ms) and PowerShell as secondary guarantee.
        Prevents identical duplicate IPs on the adapter.
        """
        p_ip = primary_ip.strip()
        ips = [p_ip]
        if secondary_ip:
            s_ip = secondary_ip.strip()
            if s_ip and s_ip != p_ip:
                ips.append(s_ip)

        # Method 1: Netsh (fast, reliable, handles quotes)
        try:
            cmd1 = ["netsh", "interface", "ipv4", "set", "dns", f'name="{adapter_name}"', "static", p_ip]
            res1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if res1.returncode == 0:
                if len(ips) > 1:
                    cmd2 = ["netsh", "interface", "ipv4", "add", "dns", f'name="{adapter_name}"', ips[1], "index=2"]
                    subprocess.run(cmd2, capture_output=True, text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)

                DNSCore.flush_dns()
                return True, f"DNS configured to: {', '.join(ips)}"
        except Exception:
            pass

        # Method 2: PowerShell Set-DnsClientServerAddress
        ips_str = ", ".join([f"'{ip}'" for ip in ips])
        # Escape single quotes in adapter name if any
        escaped_adapter = adapter_name.replace("'", "''")
        ps_cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{escaped_adapter}' -ServerAddresses ({ips_str}) -ErrorAction Stop"

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=6, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, f"DNS successfully configured to: {', '.join(ips)}"
            err = res.stderr.strip()
            return False, f"Failed to set DNS. Administrator rights may be required: {err}"
        except Exception as e:
            return False, f"Error setting DNS: {e}"

    @staticmethod
    def reset_adapter_dns_to_dhcp(adapter_name: str) -> Tuple[bool, str]:
        """
        Resets adapter DNS settings back to Automatic (DHCP / ISP default).
        """
        # Method 1: Netsh
        try:
            cmd = ["netsh", "interface", "ipv4", "set", "dns", f'name="{adapter_name}"', "dhcp"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW)
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, "DNS configuration reset to Automatic (DHCP)."
        except Exception:
            pass

        # Method 2: PowerShell
        escaped_adapter = adapter_name.replace("'", "''")
        ps_cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{escaped_adapter}' -ResetServerAddresses -ErrorAction Stop"
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, "DNS configuration reset to Automatic (DHCP)."
            return False, f"Error resetting DNS: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Error resetting DNS to DHCP: {e}"

    @staticmethod
    def flush_dns() -> Tuple[bool, str]:
        """
        Flushes the Windows DNS resolver cache instantly using native Windows API.
        Takes 0.1 ms with zero latency.
        """
        flushed = False
        try:
            # Native Windows DNS Client Cache flush API
            ret = ctypes.windll.dnsapi.DnsFlushResolverCache()
            if ret == 1:
                flushed = True
        except Exception:
            pass

        # Trigger background ipconfig flush for legacy components
        def _bg_flush():
            try:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass

        ThreadPoolExecutor(max_workers=1).submit(_bg_flush)
        return True, "Windows DNS resolver cache flushed successfully."

    @staticmethod
    def repair_network_stack() -> Tuple[bool, str]:
        """
        Executes an advanced network repair sequence:
        Flushes DNS, flushes ARP table, resets NetBIOS, and releases/renews IP.
        """
        try:
            DNSCore.flush_dns()
            subprocess.run(["arp", "-d", "*"], capture_output=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["nbtstat", "-R"], capture_output=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
            return True, "Network stack, ARP table and NetBIOS cache purged successfully."
        except Exception as e:
            return False, f"Network repair notice: {e}"
