import subprocess
import time
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import dns.resolver

class DNSCore:
    @staticmethod
    def get_network_adapters() -> List[Dict]:
        """
        Discovers all active and inactive network adapters and their current DNS configuration.
        """
        adapters = []
        ps_cmd = (
            "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=6, creationflags=subprocess.CREATE_NO_WINDOW
            )
            import json
            raw = res.stdout.strip()
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name", "")
                    status = item.get("Status", "Unknown")
                    desc = item.get("InterfaceDescription", "")
                    link_speed = item.get("LinkSpeed", "N/A")
                    mac = item.get("MacAddress", "")
                    current_dns = DNSCore.get_adapter_dns(name)
                    is_up = str(status).lower() == "up"

                    adapters.append({
                        "name": name,
                        "status": status,
                        "desc": desc,
                        "link_speed": link_speed,
                        "mac": mac,
                        "is_up": is_up,
                        "current_dns": current_dns
                    })
        except Exception as e:
            print(f"[DNSCore] Error enumerating network adapters via PowerShell: {e}")
            adapters = DNSCore._get_adapters_fallback()

        # If still empty, use fallback
        if not adapters:
            adapters = DNSCore._get_adapters_fallback()

        return adapters

    @staticmethod
    def _get_adapters_fallback() -> List[Dict]:
        """Fallback adapter detection using netsh command."""
        adapters = []
        try:
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
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
        Determines the primary connected adapter with internet access (e.g., Ethernet or Wi-Fi).
        """
        adapters = DNSCore.get_network_adapters()
        if not adapters:
            return "Ethernet"

        # 1. Prefer 'Up' Ethernet adapters
        for a in adapters:
            if a["is_up"] and "ethernet" in a["name"].lower():
                return a["name"]

        # 2. Prefer 'Up' Wi-Fi adapters
        for a in adapters:
            if a["is_up"] and any(kw in a["name"].lower() for kw in ("wi-fi", "wifi", "wlan")):
                return a["name"]

        # 3. Any adapter that is 'Up'
        for a in adapters:
            if a["is_up"]:
                return a["name"]

        return adapters[0]["name"]

    @staticmethod
    def get_adapter_dns(adapter_name: str) -> List[str]:
        """
        Returns the configured IPv4 DNS server addresses for the given adapter.
        """
        dns_servers = []
        ps_cmd = (
            f"(Get-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue).ServerAddresses"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if line and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    if line not in dns_servers:
                        dns_servers.append(line)
        except Exception:
            pass

        # Fallback to netsh if empty
        if not dns_servers:
            try:
                res = subprocess.run(
                    ["netsh", "interface", "ip", "show", "dns", f"name={adapter_name}"],
                    capture_output=True, text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW
                )
                for line in res.stdout.splitlines():
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        ip = match.group(1)
                        if ip not in dns_servers:
                            dns_servers.append(ip)
            except Exception:
                pass

        return dns_servers

    @staticmethod
    def test_dns_server(server_ip: str, domain: str = "google.com", timeout: float = 1.5) -> Tuple[bool, float, str]:
        """
        Directly queries a specific DNS server IP for resolution latency and reachability.
        Returns: (is_success, latency_ms, resolved_ip_or_error)
        """
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server_ip]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        t_start = time.perf_counter()
        try:
            answers = resolver.resolve(domain, "A")
            latency_ms = round((time.perf_counter() - t_start) * 1000, 1)
            ips = [r.to_text() for r in answers]
            return True, latency_ms, ", ".join(ips[:2])
        except dns.resolver.LifetimeTimeout:
            return False, 9999.0, "Timeout / Filtered"
        except dns.resolver.NXDOMAIN:
            return False, 9999.0, "Domain Not Found (NXDOMAIN)"
        except dns.resolver.NoNameservers:
            return False, 9999.0, "No Response from Nameserver"
        except Exception as e:
            return False, 9999.0, str(type(e).__name__)

    @staticmethod
    def test_current_dns_health(test_domains: Optional[List[str]] = None, timeout: float = 1.5) -> Tuple[bool, float, str]:
        """
        Verifies active system DNS resolution health across multiple reliable test domains.
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
            except Exception:
                continue

        return False, 9999.0, "All test domains failed to resolve"

    @staticmethod
    def benchmark_all_servers(dns_pool: List[Dict], domain: str = "google.com", timeout: float = 1.5) -> List[Dict]:
        """
        Benchmarks all DNS servers in the pool in parallel for latency and uptime.
        """
        results = []

        def _worker(entry: Dict) -> Dict:
            name = entry.get("name", "Unknown")
            primary_ip = entry.get("primary", "")
            secondary_ip = entry.get("secondary", "")
            category = entry.get("category", "General")
            desc = entry.get("desc", "")
            is_custom = entry.get("is_custom", False)

            ok_pri, ms_pri, msg_pri = DNSCore.test_dns_server(primary_ip, domain, timeout)
            ok_sec, ms_sec, msg_sec = (False, 9999.0, "None")
            if secondary_ip and secondary_ip.strip():
                ok_sec, ms_sec, msg_sec = DNSCore.test_dns_server(secondary_ip.strip(), domain, timeout)

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

        with ThreadPoolExecutor(max_workers=min(len(dns_pool) or 1, 16)) as executor:
            future_to_entry = {executor.submit(_worker, item): item for item in dns_pool}
            for future in as_completed(future_to_entry):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    item = future_to_entry[future]
                    results.append({
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
                    })

        # Sort alive servers by lowest latency first, offline servers to the bottom
        results.sort(key=lambda x: (0 if x["is_alive"] else 1, x["latency_ms"]))
        return results

    @staticmethod
    def set_adapter_dns(adapter_name: str, primary_ip: str, secondary_ip: Optional[str] = None) -> Tuple[bool, str]:
        """
        Applies primary and secondary DNS server addresses to the specified network adapter.
        """
        ips = [primary_ip.strip()]
        if secondary_ip and secondary_ip.strip():
            ips.append(secondary_ip.strip())

        # 1. Primary Method: PowerShell Set-DnsClientServerAddress
        ips_str = ", ".join([f"'{ip}'" for ip in ips])
        ps_cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ServerAddresses ({ips_str}) -ErrorAction Stop"

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=7, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, f"DNS successfully configured to: {', '.join(ips)}"
            err = res.stderr.strip()
        except Exception as e:
            err = str(e)

        # 2. Fallback Method: netsh
        try:
            res1 = subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", f"name={adapter_name}", "static", primary_ip.strip()],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if secondary_ip and secondary_ip.strip():
                subprocess.run(
                    ["netsh", "interface", "ip", "add", "dns", f"name={adapter_name}", secondary_ip.strip(), "index=2"],
                    capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
                )
            if res1.returncode == 0:
                DNSCore.flush_dns()
                return True, f"DNS configured via netsh: {', '.join(ips)}"
            else:
                return False, f"Failed to set DNS. Administrative privileges may be required: {res1.stderr.strip() or err}"
        except Exception as e:
            return False, f"Error setting DNS: {e}"

    @staticmethod
    def reset_adapter_dns_to_dhcp(adapter_name: str) -> Tuple[bool, str]:
        """
        Resets adapter DNS settings back to Automatic (DHCP / ISP default).
        """
        ps_cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ResetServerAddresses -ErrorAction Stop"
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=6, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, "DNS configuration reset to Automatic (DHCP)."
        except Exception:
            pass

        # Fallback to netsh
        try:
            res = subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", f"name={adapter_name}", "dhcp"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res.returncode == 0:
                DNSCore.flush_dns()
                return True, "DNS reset to DHCP successfully via netsh."
            return False, f"Error: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Error resetting DNS to DHCP: {e}"

    @staticmethod
    def flush_dns() -> Tuple[bool, str]:
        """
        Flushes the Windows DNS resolver cache and PowerShell DnsClient cache.
        """
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Clear-DnsClientCache -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True, "Windows DNS resolver cache flushed successfully."
        except Exception as e:
            return False, f"DNS cache flush error: {e}"
