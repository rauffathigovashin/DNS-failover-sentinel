# 🛡️ DNS Shield Pro (v2.0)
### Automated Windows DNS Sentinel, Latency Benchmarking & Zero-Downtime Failover

**DNS Shield Pro** is a high-performance Windows network utility engineered to monitor your internet DNS health in real-time, eliminate `DNS_PROBE_FINISHED_NXDOMAIN` or "Server IP address could not be found" outages, and automatically switch to the fastest, uncensored DNS server the moment your active provider degrades or throttles.

---

## ⚡ Why Was DNS Shield Pro Created?
Many ISPs silently filter, throttle, or experience packet loss on port 53 UDP toward default addresses (such as `1.1.1.1` or `9.9.9.9`). When this occurs:
- Web pages hang for 10–30 seconds before timing out.
- Windows marks your connection as "No Internet Access".
- Alternative Anycast DNS servers (`1.0.0.1` at ~5ms, `8.8.8.8` at ~30ms, `149.112.112.112`) often remain lightning-fast and unrestricted.

**DNS Shield Pro** solves this permanently by acting as an intelligent watchdog:
1. **Continuous Multi-Domain Probing**: Measures real-time latency (ms) across multiple target domains.
2. **Instant Emergency Failover**: If your active resolver fails consecutive queries, it benchmarks the entire catalog and switches your adapter to the fastest working server in milliseconds.
3. **Automated Cache Clearing**: Flushes Windows DNS Resolver Cache (`ipconfig /flushdns` and `Clear-DnsClientCache`) to immediately unfreeze blocked web sessions.
4. **Zero-Touch Background Daemon**: Sits unobtrusively in your Windows System Tray notification area.

---

## 🚀 How to Run

### Method 1: One-Click Admin Launcher (Recommended)
1. Double-click **`Start.bat`** (or `Admin_Start.vbs`).
2. If prompted by Windows User Account Control (UAC), click **`Yes`** (Administrator privileges are required by Windows to alter network adapter settings).
3. The modern dark interface will launch and protection will begin automatically.

### Method 2: Python Command Line
```powershell
python main.py
```

### Method 3: Silent Background Launch (Tray Only)
```powershell
python main.py --minimized
```

---

## 🌟 Key Features

- **⚡ Smart Emergency Failover:** Automatically switches to the fastest verified DNS candidate if consecutive queries fail.
- **🚀 24+ Curated DNS Providers:** 
  - **Ultra Fast**: Cloudflare (1.1.1.1, 1.0.0.1), Google Public DNS (8.8.8.8), OpenDNS (Cisco), Control D Free, Level3 / CenturyLink, GCore Anycast, Alibaba AliDNS.
  - **Security & Malware**: Quad9 Protected (9.9.9.9), Cloudflare Malware Shield (1.1.1.2), CleanBrowsing Security, Comodo Secure DNS, Control D Malware Shield.
  - **Ad-Blocking & Tracking Protection**: AdGuard Ad-Block (94.140.14.14), Control D Ad-Block, Mullvad Ad-Block.
  - **Privacy & No-Log**: Mullvad Privacy (194.242.2.2), Quad9 Uncensored, DNS.WATCH Germany, AdGuard Non-Filtering.
  - **Family & Parental Control**: Cloudflare Family (1.1.1.3), OpenDNS FamilyShield, CleanBrowsing Family, AdGuard Family.
- **⭐ Custom DNS Support:** Add and manage custom DNS servers (e.g. Pi-hole, AdGuard Home, NextDNS, local corporate resolvers) with one click.
- **📊 Real-time Latency Benchmarking:** Test every DNS provider concurrently with live color-coded ping badges (<40ms Ultra Fast, 40–100ms Good, >100ms High, Offline).
- **🧹 Instant Cache Purge:** One-click flush of both Windows resolver and DnsClient caches.
- **🔄 One-Click DHCP Reset:** Restore network adapter settings to automatic ISP default at any time.
- **🛡️ High-DPI System Tray Integration:** Color-coded status icon (Green = Protected, Amber = Probing/Warning, Red = Offline, Gray = Paused) with quick-action context menu.
- **⚙️ Fully Configurable:** Customize check frequency, failover sensitivity threshold, startup behavior, and custom test domains.

---

## 📦 Requirements

- **Operating System:** Windows 10 / Windows 11 (64-bit)
- **Python Version:** Python 3.9+
- **Dependencies:**
  ```powershell
  pip install -r requirements.txt
  ```
  *(customtkinter, dnspython, pystray, pillow, psutil)*
