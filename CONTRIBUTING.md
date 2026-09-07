# Contributing to DNS Shield Pro

Thank you for your interest in contributing! Here's how to get started.

## 🐛 Reporting Bugs

1. **Search existing issues** first to avoid duplicates.
2. Open a **New Issue** with:
   - Windows version (e.g. Windows 11 22H2)
   - Python version (`python --version`)
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Contents of `crash_log.txt` if applicable

## 💡 Feature Requests

Open a **New Issue** with the `enhancement` label and describe:
- What problem it solves
- Your proposed solution or approach

## 🔧 Pull Requests

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```
2. Make your changes following the code style below.
3. Test on Windows 10 and/or Windows 11.
4. Open a Pull Request with a clear description of your changes.

## 📝 Code Style

- **Python 3.9+** compatible code only.
- Use type hints for all function signatures.
- Keep functions focused — prefer small, well-named functions.
- All UI updates from background threads **must** use `root.after(0, fn)` or `_safe_call()`.
- No subprocess calls inside the monitor loop — use native `winreg` / `psutil` / `ctypes` instead.
- All UI text must be in **English**.
- Add docstrings to all public methods.

## 🧪 Testing Before Submitting

Run the syntax check:
```powershell
python -c "import py_compile; [py_compile.compile(f, doraise=True) for f in ['main.py','dns_core.py','dns_monitor.py','config_manager.py','app_gui.py','tray_manager.py']]"
```

Test the core engine:
```powershell
python -c "from dns_core import DNSCore; print(DNSCore.get_network_adapters()); print(DNSCore.flush_dns())"
```
