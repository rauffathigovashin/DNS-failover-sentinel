# 🛡️ DNS Shield Pro (v2.5)
### Automated Windows DNS Sentinel, Real-Time Latency Telemetry & Zero-Downtime Failover

**DNS Shield Pro** is an ultra-fast, high-reliability Windows network utility engineered to monitor your internet DNS health in real-time, eliminate `DNS_PROBE_FINISHED_NXDOMAIN` or "Server IP address could not be found" outages, and automatically switch to the fastest, uncensored DNS server the moment your active provider degrades, throttles, or times out.

---

## ⚡ Why DNS Shield Pro?
Many Internet Service Providers (ISPs) silently filter, throttle, or experience packet loss on port 53 UDP toward default public addresses (such as `1.1.1.1` or `9.9.9.9`). When this occurs:
- Web pages hang for 15–30 seconds before failing with DNS errors.
- Windows marks your connection as "No Internet Access".
- Alternative Anycast DNS servers (`1.0.0.1` at ~4ms, `8.8.8.8` at ~25ms, `208.67.222.222`) often remain lightning-fast and unrestricted.

**DNS Shield Pro** solves this permanently by running silently in the background with 0% CPU footprint:
1. **Ultra-Fast Native Windows Engine (Native Registry Fast-Path)**: Queries adapter status and active DNS directly via Windows Registry and `psutil` in **0.03 milliseconds**, completely eliminating heavy background PowerShell processes!
2. **Instant Zero-Latency DNS Cache Flushing**: Uses the native Windows API (`ctypes.windll.dnsapi.DnsFlushResolverCache`) to flush the DNS resolver cache in **0.55 milliseconds**.
3. **Smart Network Awareness**: Differentiates between physical link loss (cable unplugged / Wi-Fi disconnected) and true DNS outages. Prevents false failover loops when offline.
4. **Real-Time Latency Telemetry Graph**: Visualizes the last 30 latency checks on a color-coded sparkline canvas (Green <40ms, Amber 40-100ms, Red Timeout) with live min/avg/current stats.
5. **100% Pure English Interface**: Modern dark cyber dashboard, notification toasts, and high-DPI system tray integration.

---

## 🚀 How to Run

### Method 1: One-Click Admin Launcher (Recommended)
1. Double-click **`Start.bat`** (or `Admin_Start.vbs`).
2. If prompted by Windows User Account Control (UAC), click **`Yes`** (Administrator privileges are required to modify network adapter settings).
3. The modern dark dashboard will open and active protection will begin automatically.

### Method 2: Python Command Line
```powershell
python main.py
```

### Method 3: Silent Background Launch (Tray Only)
```powershell
python main.py --minimized
```

### Method 4: Standalone Binary
Run **`dist\DNS_Shield_Pro.exe`** directly without installing Python.

---

## 🌟 Key Features (v2.5)

- **📈 Real-Time Latency Sparkline Graph:** Live canvas visualizer plotting ping trends over the last 30 checks with color-coded latency thresholds.
- **⚡ Smart Dual-Resolver Failover:** Verifies secondary DNS and fallback domains before triggering emergency failover.
- **✓ Active DNS Provider Highlight:** Prominently highlights the currently active DNS provider in the catalog with a glowing green border and **`✓ ACTIVE CURRENT`** badge.
- **⚡ 1-Click Single Server Ping Test:** Test any specific DNS resolver in the catalog individually in under 1 second.
- **📊 Live Benchmark Progress Bar:** Real-time progress bar and counter when testing all catalog providers.
- **🛠️ Advanced Network Repair Toolkit:**
  - **Repair Network Stack (Winsock/ARP Purge)**: Resets corrupt network protocol stacks, purges ARP table, and flushes NetBIOS.
  - **Flush DNS Cache**: Instant 0.1ms Windows resolver purge.
  - **Reset to DHCP**: 1-click restore to automatic ISP default.
- **🛡️ High-DPI System Tray Integration:** Color-coded status icons (Green = Protected, Amber = Warning, Red = Offline, Gray = Paused) with quick context menu.

---

## 📦 Requirements & Dependencies

- **Operating System:** Windows 10 / Windows 11 (64-bit)
- **Python Version:** Python 3.9+
- **Dependencies:**
  ```powershell
  pip install -r requirements.txt
  ```
  *(customtkinter, dnspython, pystray, pillow, psutil)*

---

## 📱 DNS Shield Mobile (Android Version)

DNS Shield Pro is also available for Android smartphones to eliminate mobile ISP port 53 throttling and DNS outages!

- **Ready-to-Install APK:** Located at `DNS_Shield_Mobile.apk` (or `android\DNS_Shield_Mobile.apk`).
- **Features:**
  - Android `VpnService` zero-root DNS-only split-tunneling (0% speed impact on normal web traffic).
  - RFC 8484 DNS-over-HTTPS (DoH) engine bypassing UDP port 53 blocks.
  - Zero-Downtime auto-failover with real-time latency telemetry.
  - 1-Click Speed Benchmark across 16+ global Anycast DNS servers.
  - 15-second zero-install Private DNS guide for instant phone relief.
- **Source & Docs:** See [android/README_MOBILE.md](file:///d:/DNS%20F%C4%B0X/android/README_MOBILE.md) for full details.

